"""
Shared base for VXLAN ECN tests (L2VNI and L3VNI).

This module collects symbols that are identical across
test_v6_ecn_vxlan_l2vni_2x2.py and test_v6_ecn_vxlan_l3vni_2x2.py so the
two test files can stay in sync and shrink over time.

Phase 1 of the extraction (current file content):
    - ECN/ECT constants
    - Congestion-point -> nodes/role mapping dictionaries
    - Stateless utility helpers (get_nodes, config_node, get_xoff_rate,
      get_pfc_rx_count)

Larger pieces (run_ecn_xoff_test, _run_and_report, module_setup) will be
extracted in later phases once a hook/callback API stabilises.
"""

from spytest import st, tgapi

import qos_test_utils as qos_utils
import gamut_qos_utils as gamut_utils
import tests.cisco.tortuga.vxlan.vxlan_utils as vxlan_obj
import traffic_stream_ixia_api as stream_api


# ---------------------------------------------------------------------------
# ECN/ECT constants
# ---------------------------------------------------------------------------
ECN_NOT_ECT = 0b00
ECN_ECT_01 = 0b01
ECN_ECT_10 = 0b10
ECN_CE = 0b11


# Stable, CSV-friendly labels for sub-test ids (validator umbrella tests use
# these to construct tcid strings like "L2vniEcnMark_spine_egress_Ect10").
_ECT_LABELS = {
    ECN_NOT_ECT: 'NotEct',
    ECN_ECT_01:  'Ect01',
    ECN_ECT_10:  'Ect10',
    ECN_CE:      'Ce',
}


def ect_label(ect):
    """Return short stable label for an ECT codepoint (NotEct/Ect01/Ect10/Ce)."""
    return _ECT_LABELS.get(int(ect), f"Ect{int(ect):02b}")


# ---------------------------------------------------------------------------
# Congestion-point mappings
# ---------------------------------------------------------------------------
# Map congestion point to nodes where ECN marking should occur
# (i.e., the target nodes that have ECN enabled)
ECN_MARKING_NODES = {
    'ingress_leaf_egress': ['leaf0'],            # ECN enabled only on leaf0
    'spine_egress':        ['spine0', 'spine1'], # ECN enabled on both spines
    'egress_leaf_tgen':    ['leaf1'],            # ECN enabled only on leaf1
}

# Map congestion point -> topology role of the node(s) that should mark.
# Used to derive marking_nodes from data.topology when available, falling
# back to ECN_MARKING_NODES (above) for compatibility.
CONGESTION_TO_MARKING_ROLE = {
    'ingress_leaf_egress': 'ingress_leaf',
    'spine_egress':        'spine',
    'egress_leaf_tgen':    'egress_leaf',
}

# Map congestion point to nodes where PFC XOFF should be received
# (i.e., the node at the congestion point receives XOFF from downstream)
PFC_XOFF_NODES = {
    'ingress_leaf_egress': ['leaf0'],            # leaf0 receives XOFF from spines
    'spine_egress':        ['spine0', 'spine1'], # spines receive XOFF from leaf1
    'egress_leaf_tgen':    ['leaf1'],            # leaf1 receives XOFF from TGEN
}


# ---------------------------------------------------------------------------
# Stateless utility helpers
# ---------------------------------------------------------------------------
def get_nodes():
    """Get node mapping using shared utility."""
    return qos_utils.get_nodes()


def config_node(node, config, type='', skip_errors=False):
    if type:
        st.config(node, config, type=type, skip_error_check=skip_errors, conf=True)
    else:
        st.config(node, config, skip_error_check=skip_errors, conf=True)


def config_static(node, config_domain, config_list, add=True):
    """Configure or deconfigure static configs from a YAML config_list.

    Args:
        node: Node name (e.g., 'leaf0', 'spine0')
        config_domain: 'sonic' or 'bgp'
        config_list: Pre-loaded YAML config dictionary
        add: True to configure, False to deconfigure
    """
    nodes = qos_utils.get_nodes()
    domain = 'vtysh' if config_domain == 'bgp' else ''

    if add:
        config_node(nodes[node], config_list[node][config_domain]['config'], domain)
    else:
        config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain, skip_errors=True)


def get_xoff_rate(port_speed_gbps):
    """
    Calculate PFC XOFF frame rate based on port speed.

    Formula: rate = port_speed_gbps * 10 fps
        100G -> 1000 fps
        200G -> 2000 fps
        400G -> 4000 fps
        800G -> 8000 fps

    Args:
        port_speed_gbps: Port speed in Gbps

    Returns:
        int: XOFF frame rate in frames per second
    """
    return port_speed_gbps * 10


def ingress_leaf_speeds(topology):
    """Return (ingress_bw, egress_bw) Gbps for the ingress leaf, from a
    populated topology dict (build_node_topology + populate_topology_speeds).

    ingress_bw = TGEN-facing port speed.
    egress_bw  = min of fabric uplink port speeds (single-flow ECMP picks one).

    Returns (0, 0) if either side cannot be derived.
    """
    if not topology:
        return 0, 0
    for node, entry in topology.items():
        if entry.get('role') != 'ingress_leaf':
            continue
        speeds = entry.get('port_speeds') or {}
        tgen_port = entry.get('tgen_port')
        ingress_bw = int(speeds.get(tgen_port, 0)) if tgen_port else 0
        fabric_speeds = [int(speeds.get(p, 0))
                         for p in (entry.get('egress_ports') or [])
                         if p and p != tgen_port and speeds.get(p)]
        egress_bw = min(fabric_speeds) if fabric_speeds else 0
        return ingress_bw, egress_bw
    return 0, 0


def get_pfc_rx_count(dut, port, priority):
    """
    Get PFC Rx frame count for given port and priority.

    Args:
        dut: DUT handle
        port: Interface name
        priority: Priority/TC value (0-7)

    Returns:
        int: Count of PFC frames received
    """
    priority = int(priority)
    cmd = f"show pfc counters | sed -n '/Port Rx/,/^$/p' | grep {port}"
    st.log(f"Reading PFC Rx counters: port={port}, priority={priority}")
    try:
        output = st.show(dut, cmd, skip_tmpl=True)
        if isinstance(output, list):
            line = next((l for l in output if port in l), None)
        else:
            lines = output.strip().split('\n')
            line = next((l for l in lines if port in l), None)

        if line:
            parts = line.split()
            # Format: PortName  PFC0  PFC1  PFC2  PFC3  PFC4  PFC5  PFC6  PFC7
            if len(parts) > priority + 1:
                count = int(parts[priority + 1].replace(',', ''))
                st.log(f"PFC Rx count for port={port}, priority={priority}: {count}")
                return count
    except Exception as e:
        st.log(f"Error reading PFC Rx counters: {e}")
    return 0


# ---------------------------------------------------------------------------
# TGEN interface + traffic stream setup (shared)
# ---------------------------------------------------------------------------
def setup_tgen_interfaces_and_stream(data, tc, rate_percent, ect=ECN_ECT_10,
                                     post_handles_hook=None):
    """
    Configure TGEN interfaces and create a single data stream from
    T1D3P1 to T1D4P1.

    Args:
        data: Per-test SpyTestDict carrying TGEN IP/MAC/VLAN/etc.
        tc: Traffic class for DSCP mapping
        rate_percent: Rate as percentage of line rate
        ect: ECN codepoint (default ECT(10))
        post_handles_hook: Optional callable(handles, int_dict) invoked after
            NGPF interface configuration. Used by L3VNI tests to perform
            gateway ND resolution before the end-to-end ping.

    Returns:
        tuple: (streams_dict, handles, int_dict)
    """
    nodes = qos_utils.get_nodes()

    # Get DSCP value for the target TC
    dscp = qos_utils.convert_tc_to_dscp(nodes['leaf0'], tc)
    st.log(f"Using DSCP {dscp} for TC {tc}, ECT={ect}")

    # Configure TGEN interfaces - source and destination only
    int_dict = {
        'T1D3P1': {
            'host_ip': data.t1d3p1_ip6_addr,
            'gateway': data.d3t1_ip6_addr,
            'mac': data.t1d3p1_mac_addr
        },
        'T1D4P1': {
            'host_ip': data.t1d4p1_ip6_addr,
            'gateway': data.d4t1_ip6_addr,
            'mac': data.t1d4p1_mac_addr
        },
    }

    # Create NGPF topologies for IPv6 endpoints
    st.banner("Configuring TGEN IPv6 interfaces via NGPF")
    handles = vxlan_obj.config_tgen_interface(int_dict, 'ipv6')

    # L3VNI / other-mode hook: e.g. ND gateway resolution
    if post_handles_hook is not None:
        try:
            post_handles_hook(handles, int_dict)
        except Exception as hook_err:
            st.log(f"post_handles_hook failed (non-fatal): {hook_err}")

    # Set up traffic parameters in data object for config_traffic_item
    data.ip_dscp = int(dscp)
    data.traffic_class = int(dscp) << 2
    data.transmit_mode = 'continuous'
    data.pkts_per_burst = '100000'
    data.circuit_endpoint_type = 'ipv6'

    # Save original rate_percent and set requested rate
    orig_rate = data.rate_percent
    data.rate_percent = str(rate_percent)

    # Single stream: T1D3P1 -> T1D4P1
    stream_list = [('T1D3P1', 'T1D4P1')]

    st.banner(f"Creating data stream T1D3P1->T1D4P1 at {rate_percent}% with ping verification")
    streams = vxlan_obj.config_traffic_item(
        stream_list, handles, int_dict, data,
        ping=True, dscp=int(dscp), bidirectional=0, ect=ect
    )

    # Set PFC priority group for the traffic stream
    for key, item in streams.items():
        stream_api.set_pfc_priority_group(item['tg_handle'], item['traffic_result'], tc)
        st.log(f"Set PFC priority group {tc} for stream {key}")

    # Restore original rate_percent
    data.rate_percent = orig_rate

    return streams, handles, int_dict


def setup_tgen_interfaces_and_streams_2to1(data, tc, rate_percent,
                                           ect=ECN_ECT_10,
                                           post_handles_hook=None):
    """Two ingress streams (T1D3P1, T1D3P2) -> single egress T1D4P1.

    Both ingress NGPF endpoints live in the same subnet on leaf0 (caller is
    expected to have added T1D3P2 as a VLAN member alongside T1D3P1), so
    they share data.d3t1_ip6_addr as gateway. Requires:
        data.t1d3p2_ip6_addr, data.t1d3p2_mac_addr

    Mirrors setup_tgen_interfaces_and_stream() in every other respect so it
    can be used as a drop-in ``stream_setup_fn`` for run_ecn_xoff_test().
    Returns (streams_dict, handles, int_dict).
    """
    nodes = qos_utils.get_nodes()
    dscp = qos_utils.convert_tc_to_dscp(nodes['leaf0'], tc)
    st.log(f"Using DSCP {dscp} for TC {tc}, ECT={ect} (2->1 ingress)")

    int_dict = {
        'T1D3P1': {
            'host_ip': data.t1d3p1_ip6_addr,
            'gateway': data.d3t1_ip6_addr,
            'mac': data.t1d3p1_mac_addr,
        },
        'T1D3P2': {
            'host_ip': data.t1d3p2_ip6_addr,
            'gateway': data.d3t1_ip6_addr,
            'mac': data.t1d3p2_mac_addr,
        },
        'T1D4P1': {
            'host_ip': data.t1d4p1_ip6_addr,
            'gateway': data.d4t1_ip6_addr,
            'mac': data.t1d4p1_mac_addr,
        },
    }

    st.banner("Configuring TGEN IPv6 interfaces via NGPF (2 ingress + 1 egress)")
    handles = vxlan_obj.config_tgen_interface(int_dict, 'ipv6')

    if post_handles_hook is not None:
        try:
            post_handles_hook(handles, int_dict)
        except Exception as hook_err:
            st.log(f"post_handles_hook failed (non-fatal): {hook_err}")

    data.ip_dscp = int(dscp)
    data.traffic_class = int(dscp) << 2
    data.transmit_mode = 'continuous'
    data.pkts_per_burst = '100000'
    data.circuit_endpoint_type = 'ipv6'

    orig_rate = data.rate_percent
    data.rate_percent = str(rate_percent)

    stream_list = [('T1D3P1', 'T1D4P1'), ('T1D3P2', 'T1D4P1')]
    st.banner(
        f"Creating 2 data streams [T1D3P1->T1D4P1, T1D3P2->T1D4P1] "
        f"at {rate_percent}% each with ping verification"
    )
    streams = vxlan_obj.config_traffic_item(
        stream_list, handles, int_dict, data,
        ping=True, dscp=int(dscp), bidirectional=0, ect=ect
    )

    for key, item in streams.items():
        stream_api.set_pfc_priority_group(item['tg_handle'], item['traffic_result'], tc)
        st.log(f"Set PFC priority group {tc} for stream {key}")

    data.rate_percent = orig_rate
    return streams, handles, int_dict


# ---------------------------------------------------------------------------
# Generic ECN test runner using PFC XOFF backpressure (shared body).
# ---------------------------------------------------------------------------
# Hooks let L2VNI / L3VNI override the small parts that genuinely differ:
#   - diagnostics_hook(nodes, phase): per-test "show MAC/EVPN/VRF/..." dump.
#   - pre_ngpf_diagnostics_hook(nodes): optional verbose pre-NGPF dump
#       (L3VNI uses this to print VRF/EVPN/route state right before TGEN
#       NGPF setup, plus a leaf0->leaf1 ping6 through Vrf01).
#   - setup_tgen_post_handles_hook(handles, int_dict): forwarded to
#       setup_tgen_interfaces_and_stream() (e.g. L3VNI gateway ND ping).
# Behaviour-affecting flags:
#   - clear_wred_pre_traffic (default True): L2VNI clears WRED counters
#       and queue watermarks before traffic; L3VNI currently skips that
#       to preserve the existing comment-out behaviour.
#   - save_config_nodes: list of node names whose running config is saved
#       at the end; defaults to ['leaf0','leaf1','spine0','spine1'].
# ---------------------------------------------------------------------------
def run_ecn_xoff_test(data, congestion_point, test_name,
                      ect=ECN_ECT_10,
                      *,
                      port_speed_gbps,
                      vtep_ips,
                      diagnostics_hook,
                      pre_ngpf_diagnostics_hook=None,
                      setup_tgen_post_handles_hook=None,
                      clear_wred_pre_traffic=True,
                      save_config_nodes=None,
                      skip_pfc_xoff_stream=False,
                      stream_setup_fn=None):
    """Run one ECN-over-XOFF iteration.

    See module-level comment block for the hook/flag contract.

    Returns a TrafficRunResult dict with at minimum:
        passed (bool)             -- True unless an exception occurred during
                                     the run; data-quality verdicts are
                                     emitted by the validator umbrella tests
                                     in validators_vxlan_ecn.py
        reason (str)              -- '' on clean run; 'exception: ...' on error
        congestion_point (str)
        ect (int)
        test_name (str)
        marking_role (str)
        marking_nodes (list[str])
        marking_node_platforms (list[str])
        snapshot_summary (dict)   -- per-node totals + per-port deltas
        pfc_info (dict)           -- per-node per-intf {before, after}
        pfc_xoff_nodes (list[str])
        congestion_pfc_delta (int)
        capture_results (dict)    -- {'T1D4P1': {analyzed_frames, ecn_counts, ...}}
        tx_frames (int)
        rx_frames (int)
        wred_summary (dict)
        ecn_marked_per_node (dict)
        total_ecn_marked (int)
        wred_total_packets (int)
        wred_total_ecn_marked (int)
        captured_frames (int)
        exception (str|None)
    """
    leaf0_vtep_ip, leaf1_vtep_ip = vtep_ips
    if save_config_nodes is None:
        save_config_nodes = ['leaf0', 'leaf1', 'spine0', 'spine1']

    vars = st.get_testbed_vars()
    nodes = qos_utils.get_nodes()

    # Result bundle accumulated throughout the run; returned at the end.
    # Note: bundle['passed'] indicates only that the run completed without
    # an exception. Data-quality verdicts (throughput, ECN marking, drops,
    # PFC XOFF, PG drops) are emitted by validators in validators_vxlan_ecn.py
    # via the umbrella tests in test_v6_ecn_vxlan_l{2,3}vni_2x2.py.
    bundle = {
        'passed': True,
        'reason': '',
        'congestion_point': congestion_point,
        'ect': int(ect),
        'test_name': test_name,
        'marking_role': None,
        'marking_nodes': [],
        'marking_node_platforms': [],
        'snapshot_summary': {},
        'pfc_info': {},
        'pfc_xoff_nodes': [],
        'congestion_pfc_delta': 0,
        'capture_results': {},
        'tx_frames': 0,
        'rx_frames': 0,
        'wred_summary': {},
        'ecn_marked_per_node': {},
        'total_ecn_marked': 0,
        'wred_total_packets': 0,
        'wred_total_ecn_marked': 0,
        'captured_frames': 0,
        'exception': None,
        # Natural-congestion / no-PFC-XOFF accessors (always populated):
        'skip_pfc_xoff_stream': bool(skip_pfc_xoff_stream),
        'ingress_load_pct': float(getattr(data, 'rate_percent', 0) or 0),
        'frame_size': int(getattr(data, 'frame_size', 0) or 0),
        'traffic_run_time': int(getattr(data, 'traffic_run_time', 0) or 0),
        'port_speeds_per_node': {},
    }

    streams = None
    handles = None
    xoff_stream_id = None
    saved_ecn_state = {}
    capture_started = False
    wred_before = {}
    wred_after = {}
    wred_summary = {}
    watermarks = {}
    snapshot_before = {}
    snapshot_after = {}
    snapshot_summary = {}

    # Define interfaces for WRED counter capture on all 4 nodes
    # With XOFF-based congestion, we only need 1 port per leaf-spine link
    wred_interfaces = {
        'leaf0': [vars.D3D1P1] + ([vars.D3D2P1] if hasattr(vars, 'D3D2P1') else []),
        'spine0': [vars.D1D4P1] if hasattr(vars, 'D1D4P1') else [],
        'leaf1': [vars.D4T1P1]
    }
    st.log(f"WRED interfaces for counter capture: {wred_interfaces}")

    try:
        st.banner("Verifying VTEP state before test")
        try:
            vxlan_obj.verify_vtep_state_v6(nodes, leaf0_vtep_ip, leaf1_vtep_ip)
        except Exception as vtep_err:
            st.error(f"VTEP verification failed: {vtep_err}")
            diagnostics_hook(nodes, "VTEP FAILED")
            raise

        # Get TGEN handles
        tg, src_port_handle = tgapi.get_handle_byname('T1D3P1')
        tg_dst, dst_port_handle = tgapi.get_handle_byname('T1D4P1')

        # --- Packet Capture Setup (Egress Leaf Port) ---
        capture_port_handle = dst_port_handle

        # Step 1: Disable ECN on non-target nodes
        ecn_disable_nodes = qos_utils.ECN_DISABLE_MAP.get(congestion_point, [])
        ecn_enabled_nodes = ECN_MARKING_NODES.get(congestion_point, [])
        if ecn_disable_nodes:
            saved_ecn_state = qos_utils.disable_ecn_on_nodes(nodes, ecn_disable_nodes, enabled_nodes=ecn_enabled_nodes)

        # Step 2: Create PFC XOFF stream FIRST - BEFORE NGPF setup
        # This ensures the raw L2 stream is created on a clean port without NGPF interference
        # Skipped when skip_pfc_xoff_stream=True (natural-congestion test variant).
        if not skip_pfc_xoff_stream:
            xoff_rate = get_xoff_rate(port_speed_gbps)
            st.banner(f"Creating PFC XOFF stream FIRST: T1D4P1 at {xoff_rate} fps for TC3 (BEFORE NGPF)")
            xoff_stream_id = stream_api.create_pfc_xoff_stream(
                tg_dst, 'T1D4P1', data.t1d4p1_mac_addr, xoff_rate
            )

            # Apply PFC stream immediately to lock in the L2 header
            st.banner("Applying PFC stream configuration to lock in L2 header")
            tg_dst.tg_traffic_control(action='apply')
            st.wait(1)
        else:
            st.banner("skip_pfc_xoff_stream=True; NOT creating PFC XOFF generator stream from TGEN")

        # Optional pre-NGPF diagnostics (L3VNI uses this for VRF/VXLAN dumps).
        if pre_ngpf_diagnostics_hook is not None:
            try:
                pre_ngpf_diagnostics_hook(nodes)
            except Exception as pre_err:
                st.log(f"pre_ngpf_diagnostics_hook failed (non-fatal): {pre_err}")

        # Step 3: Now set up TGEN interfaces and create data stream using NGPF
        st.banner(f"Setting up TGEN interfaces and data stream at {data.rate_percent}%")
        setup_fn = stream_setup_fn or setup_tgen_interfaces_and_stream
        streams, handles, int_dict = setup_fn(
            data, data.tc, float(data.rate_percent), ect=ect,
            post_handles_hook=setup_tgen_post_handles_hook
        )

        # Get the stream_id from the streams dictionary. With the default
        # single-stream setup this is 'T1D3P1<-->T1D4P1'; with multi-stream
        # setups (e.g. 2-to-1) fall back to the first stream for logging.
        stream_key = 'T1D3P1<-->T1D4P1' if 'T1D3P1<-->T1D4P1' in streams \
            else next(iter(streams.keys()))
        data_stream_id = streams[stream_key]['stream_id']
        st.log(f"Data stream created: {stream_key} -> {data_stream_id} "
               f"(total streams: {len(streams)})")

        # Pre-traffic diagnostics
        diagnostics_hook(nodes, "PRE-TRAFFIC")

        # Step 4: Clear all DUT counters and watermarks before traffic
        # IMPORTANT: Reset Gamut hardware counters BEFORE sonic-clear so that
        # the baselines saved by sonic-clear match the zeroed hardware values.
        # If sonic-clear runs first, it saves the old hw value as baseline;
        # then gamut_clear resets hw to 0, making all subsequent reads
        # negative (clipped to 0).
        for node_name, dut in nodes.items():
            if qos_utils.detect_platform(dut) == 'n9164e':
                st.log(f"Clearing Gamut port counters on {node_name}")
                gamut_utils.gamut_clear_port_counters(dut)

        st.banner("Clearing all DUT counters and watermarks")
        for dut in st.get_dut_names():
            qos_utils.clear_all_counters(dut)

        # Step 5: Optionally clear and then capture WRED/ECN counters BEFORE traffic
        if clear_wred_pre_traffic:
            st.banner("Clearing WRED/ECN counters on all nodes")
            qos_utils.clear_all_wred_counters(nodes, wred_interfaces, tc=data.tc)

            st.banner("Clearing queue watermarks on all nodes")
            qos_utils.clear_all_queue_watermarks(nodes, wait_after=3)

        st.banner("Capturing WRED/ECN counters BEFORE traffic")
        wred_before = qos_utils.capture_wred_counters(nodes, wred_interfaces, tc=data.tc)

        # Unified per-node snapshot (parallel to legacy captures).
        if data.topology:
            try:
                snapshot_before = qos_utils.capture_node_snapshot(
                    nodes, data.topology, tc=data.tc
                )
                st.log(f"snapshot_before captured for nodes: {list(snapshot_before.keys())}")
            except Exception as snap_err:
                st.log(f"snapshot_before capture failed (non-fatal): {snap_err}")

        # Step 6: Record PFC Rx count BEFORE (after clearing) on ALL interfaces
        st.banner("Recording PFC Rx counters BEFORE traffic on all interfaces")
        pfc_before_all = {}
        for node_name, interfaces in wred_interfaces.items():
            if node_name not in nodes:
                continue
            pfc_before_all[node_name] = {}
            for intf in interfaces:
                pfc_count = get_pfc_rx_count(nodes[node_name], intf, data.tc)
                pfc_before_all[node_name][intf] = {'before': pfc_count}
                st.log(f"  {node_name} {intf} PFC_RX BEFORE: {pfc_count}")

        # Step 8: Apply all traffic (re-apply includes NGPF data stream)
        # PFC stream was applied earlier, now adding NGPF traffic
        st.banner("Applying traffic configuration (NGPF traffic)")
        tg.tg_traffic_control(action='apply')
        st.wait(2)  # Give IxNetwork time to apply

        # Step 8b: Explicitly regenerate and apply ALL traffic items via IxNetwork API
        # This ensures the PFC stream flow group is properly configured
        st.banner("Regenerating and applying ALL traffic items via IxNetwork API")
        try:
            from spytest.tgen.tg import get_ixnet
            ixnet = get_ixnet()
            traffic_items = ixnet.getList('/traffic', 'trafficItem')
            st.log(f"Found {len(traffic_items)} traffic items")
            # Must call 'generate' on each traffic item individually (generateAll doesn't exist)
            for ti in traffic_items:
                ti_name = ixnet.getAttribute(ti, '-name')
                st.log(f"  Generating traffic item: {ti_name}")
                ixnet.execute('generate', ti)
            st.log("All traffic items regenerated, applying to hardware...")
            ixnet.execute('apply', '/traffic')
            st.log("Traffic applied to hardware")
        except Exception as gen_err:
            st.error(f"IxNetwork regenerate/apply failed: {gen_err}")
            import traceback
            st.log(traceback.format_exc())
        st.wait(3)  # Give IxNetwork time to apply

        # --- Start Packet Capture on Egress Port (BEFORE traffic starts) ---
        capture_started = qos_utils.start_ecn_ce_capture(
            tg_dst, capture_port_handle, port_name='T1D4P1'
        )

        # Step 9: Start all traffic with single run command
        st.banner(f"Starting all traffic for {data.traffic_run_time} seconds")
        tg.tg_traffic_control(action='run')

        # Step 10: Wait for traffic duration
        st.wait(data.traffic_run_time)

        # Step 11: Stop all traffic
        st.banner("Stopping traffic")
        tg.tg_traffic_control(action='stop')
        st.wait(15)  # Wait for SONiC interface counters to sync

        # Poll for traffic to fully stop before collecting stats
        st.log("Polling for traffic state to settle...")
        try:
            tg.tg_traffic_control(action='poll')
            st.wait(3)
        except Exception as poll_err:
            st.log(f"Traffic poll warning (non-fatal): {poll_err}")

        # Step 12: Capture WRED/ECN counters AFTER traffic
        st.banner("Capturing WRED/ECN counters AFTER traffic")
        wred_after = qos_utils.capture_wred_counters(nodes, wred_interfaces, tc=data.tc)

        # Unified per-node snapshot AFTER traffic (parallel to legacy capture)
        if data.topology:
            try:
                snapshot_after = qos_utils.capture_node_snapshot(
                    nodes, data.topology, tc=data.tc
                )
                snapshot_summary = qos_utils.print_node_snapshot_deltas(
                    snapshot_before, snapshot_after, data.topology, tc=data.tc,
                    label=f"Per-Node Snapshot Deltas ({test_name})",
                    port_speed_gbps=port_speed_gbps,
                    traffic_duration=data.traffic_run_time,
                    frame_size=getattr(data, 'frame_size', None),
                )
            except Exception as snap_err:
                st.log(f"snapshot_after / deltas failed (non-fatal): {snap_err}")

        # Capture queue watermarks AFTER traffic
        st.banner("Capturing queue watermarks AFTER traffic")
        watermarks = qos_utils.capture_queue_watermark_values(nodes, wred_interfaces, tc=data.tc)

        # Capture PFC RX counters AFTER traffic on ALL interfaces
        st.banner("Capturing PFC Rx counters AFTER traffic on all interfaces")
        pfc_info = {}
        for node_name, interfaces in wred_interfaces.items():
            if node_name not in nodes:
                continue
            pfc_info[node_name] = {}
            for intf in interfaces:
                pfc_after = get_pfc_rx_count(nodes[node_name], intf, data.tc)
                pfc_before = pfc_before_all.get(node_name, {}).get(intf, {}).get('before', 0)
                pfc_info[node_name][intf] = {'before': pfc_before, 'after': pfc_after}
                st.log(f"  {node_name} {intf} PFC_RX AFTER: {pfc_after} (delta={pfc_after - pfc_before})")

        # Print WRED counter deltas (include watermarks and PFC info)
        wred_summary = qos_utils.print_wred_counter_deltas(
            wred_before, wred_after, tc=data.tc, label="WRED/ECN Counter Deltas",
            watermarks=watermarks, pfc_info=pfc_info
        )
        bundle['wred_summary'] = wred_summary or {}
        bundle['snapshot_summary'] = snapshot_summary or {}
        bundle['pfc_info'] = pfc_info
        # Snapshot of per-port speeds (Gbps) from data.topology so validators
        # can compute bandwidth ratios without re-querying DUTs.
        try:
            bundle['port_speeds_per_node'] = {
                n: dict((entry.get('port_speeds') or {}))
                for n, entry in (data.topology or {}).items()
            }
            # Also stash per-node tgen_port + role + ingress/egress port lists
            # so validators can identify TGEN-facing vs fabric-facing ports
            # without heuristics on snapshot counters.
            bundle['topology_min'] = {
                n: {
                    'role':           entry.get('role'),
                    'tgen_port':      entry.get('tgen_port'),
                    'ingress_ports':  list(entry.get('ingress_ports') or []),
                    'egress_ports':   list(entry.get('egress_ports') or []),
                }
                for n, entry in (data.topology or {}).items()
            }
        except Exception as _spe:
            st.log(f"port_speeds_per_node stash failed (non-fatal): {_spe}")

        # --- Stop Packet Capture and Analyze ECN (AFTER traffic stops) ---
        capture_results = {}
        if capture_started:
            pkt_dict = qos_utils.stop_packet_capture(
                tg_dst, capture_port_handle, port_name='T1D4P1',
                max_frames=data.capture_count
            )
            if pkt_dict is not None:
                cap_result = qos_utils.extract_ecn_from_capture(
                    pkt_dict, capture_port_handle, max_frames=data.capture_count
                )
                capture_results['T1D4P1'] = cap_result
                qos_utils.print_capture_ecn_summary(capture_results, "Egress TGEN Packet Capture - ECN Summary")
        bundle['capture_results'] = capture_results

        # Step 13: Verify PFC XOFF was received at congestion point
        # The PFC backpressure propagates from TGEN -> leaf1 -> spines -> leaf0
        # Check PFC XOFF at the node(s) corresponding to the congestion point
        pfc_xoff_nodes = PFC_XOFF_NODES.get(congestion_point, ['leaf1'])
        congestion_pfc_delta = 0
        for pfc_node in pfc_xoff_nodes:
            if pfc_node in pfc_info:
                for intf, pfc_data in pfc_info[pfc_node].items():
                    delta = pfc_data.get('after', 0) - pfc_data.get('before', 0)
                    congestion_pfc_delta += delta
        st.log(f"Total PFC Rx delta at congestion point ({pfc_xoff_nodes}): {congestion_pfc_delta}")
        bundle['pfc_xoff_nodes'] = list(pfc_xoff_nodes)
        bundle['congestion_pfc_delta'] = congestion_pfc_delta

        if congestion_pfc_delta <= 0:
            # Logged only; pass/fail is decided by validate_pfc_xoff().
            st.log(f"INFO: PFC XOFF runner-delta == 0 at {pfc_xoff_nodes}; "
                   f"validator will use snapshot pfc_rx counters")

        # Step 14: Get traffic statistics (TX and RX counts)
        st.banner("Reading traffic statistics")
        st.log(f"src_port_handle={src_port_handle}, dst_port_handle={dst_port_handle}, data_stream_id={data_stream_id}")

        tx_frames = 0
        rx_frames = 0

        # Method 1 (TGEN traffic_item stats) currently disabled -- timing out
        # on IxNetwork side. Falling back to DUT counters below.

        # Method 2: Fallback to DUT interface counters if TGEN stats failed
        # The TGEN-facing ports on leaf0/leaf1 give us TX/RX approximation
        stats_from_dut = False
        if tx_frames == 0 and rx_frames == 0:
            st.log("TGEN stats unavailable - using DUT interface counters as fallback")
            stats_from_dut = True
            try:
                # For Gamut (N9164E), use real-time ASIC counters instead of stale CLI counters
                # The 'show interface counters' CLI uses counterpoll cache which can be minutes stale
                # Check per-node platform type since topology may be mixed
                leaf0_platform = data.node_meta.get('leaf0', {}).get('platform_type', 'generic')
                leaf1_platform = data.node_meta.get('leaf1', {}).get('platform_type', 'generic')

                # TX: leaf0 TGEN port RX counter (packets received from TGEN into leaf0)
                if leaf0_platform == 'n9164e':
                    st.log("leaf0 (Gamut): Using real-time ASIC counters")
                    leaf0_counters = gamut_utils.gamut_get_interface_counters(nodes['leaf0'], vars.D3T1P1)
                    if leaf0_counters:
                        tx_frames = leaf0_counters.get('rx_frames', 0)
                else:
                    tx_output = st.show(nodes['leaf0'], f"show interface counters | grep {vars.D3T1P1}",
                                       skip_tmpl=True, skip_error_check=True)
                    import re
                    tx_match = re.search(r'U\s+([\d,]+)\s+', tx_output)
                    if tx_match:
                        tx_frames = int(tx_match.group(1).replace(',', ''))

                # RX: leaf1 TGEN port TX counter (packets sent from leaf1 to TGEN)
                if leaf1_platform == 'n9164e':
                    st.log("leaf1 (Gamut): Using real-time ASIC counters")
                    leaf1_counters = gamut_utils.gamut_get_interface_counters(nodes['leaf1'], vars.D4T1P1)
                    if leaf1_counters:
                        rx_frames = leaf1_counters.get('tx_frames', 0)
                else:
                    rx_output = st.show(nodes['leaf1'], f"show interface counters | grep {vars.D4T1P1}",
                                       skip_tmpl=True, skip_error_check=True)
                    import re
                    rx_full_match = re.search(r'U\s+([\d,]+)\s+[\d.]+\s+B/s\s+[\d.]+%\s+\d+\s+\d+\s+\d+\s+([\d,]+)', rx_output)
                    if rx_full_match:
                        rx_frames = int(rx_full_match.group(2).replace(',', ''))

                st.log(f"DUT-based stats: TX~={tx_frames}, RX~={rx_frames}")
            except Exception as dut_err:
                st.error(f"DUT counter fallback also failed: {dut_err}")

        st.log(f"Traffic stats: TX={tx_frames}, RX={rx_frames} (from_dut={stats_from_dut})")
        bundle['tx_frames'] = int(tx_frames)
        bundle['rx_frames'] = int(rx_frames)

        for dut in st.get_dut_names():
            st.show(dut, "show interface counters | grep -v D",
                        skip_tmpl=True, skip_error_check=True)
        # Drop counters
        drop_raw = st.show(dut, "show dropcounters count",
                        skip_tmpl=True, skip_error_check=True)

        # Gamut-specific port counters (includes ECN counters) - check per-DUT
        for node_name, dut in nodes.items():
            if qos_utils.detect_platform(dut) == 'n9164e':
                port_counters = gamut_utils.gamut_dump_port_counters(dut)
                if port_counters:
                    st.log(f"Gamut port counters for {node_name}:\n{port_counters}")

        # Calculate loss rate
        loss_rate = 0.0
        if tx_frames > 0:
            loss_rate = ((tx_frames - rx_frames) / tx_frames) * 100
        st.log(f"Packet loss rate: {loss_rate:.2f}%")

        # Compute WRED totals; surfaced in bundle for validators
        wred_total_packets = 0
        wred_total_ecn_marked = 0
        for node_name, interfaces in (wred_summary or {}).items():
            for intf, counters in interfaces.items():
                wred_total_packets += counters.get('packets', 0)
                wred_total_ecn_marked += counters.get('ecn_marked_pkts', 0)

        # Prefer snapshot-derived totals when available (snapshot covers all
        # topology ports, not just the wred_interfaces subset).
        if snapshot_summary:
            snap_total_pkts = sum(s.get('totals', {}).get('queue_packets', 0)
                                  for s in snapshot_summary.values())
            snap_total_ecn = sum(s.get('totals', {}).get('ecn_marked_pkts', 0)
                                 for s in snapshot_summary.values())
            st.log(f"Snapshot totals: queue_pkts={snap_total_pkts}, "
                   f"ecn_marked={snap_total_ecn} (wred totals: "
                   f"pkts={wred_total_packets}, ecn={wred_total_ecn_marked})")
            wred_total_packets = snap_total_pkts
            wred_total_ecn_marked = snap_total_ecn

        # Get captured frames count from packet capture
        captured_frames = 0
        if capture_results and 'T1D4P1' in capture_results:
            captured_frames = capture_results['T1D4P1'].get('analyzed_frames', 0)
        bundle['captured_frames'] = int(captured_frames)
        bundle['wred_total_packets'] = int(wred_total_packets)
        bundle['wred_total_ecn_marked'] = int(wred_total_ecn_marked)

        # Informational summary of traffic evidence; pass/fail is decided
        # by validate_throughput() in validators_vxlan_ecn.py.
        st.log(f"Traffic evidence: TX={tx_frames}, RX={rx_frames}, "
               f"WRED_pkts={wred_total_packets}, ECN_marked={wred_total_ecn_marked}, "
               f"captured={captured_frames}")
        if (rx_frames == 0 and wred_total_packets == 0 and
                wred_total_ecn_marked == 0 and captured_frames == 0):
            diagnostics_hook(nodes, "POST-TRAFFIC: no evidence of traffic")

        # Compute ECN marked packets per node from WRED summary
        ecn_marked_per_node = {}
        total_ecn_marked = 0
        for node_name, interfaces in (wred_summary or {}).items():
            node_ecn_marked = 0
            for intf, counters in interfaces.items():
                node_ecn_marked += counters.get('ecn_marked_pkts', 0)
            ecn_marked_per_node[node_name] = node_ecn_marked
            total_ecn_marked += node_ecn_marked

        # Prefer snapshot-derived per-node ECN counts when available.
        if snapshot_summary:
            ecn_marked_per_node = {
                n: s.get('totals', {}).get('ecn_marked_pkts', 0)
                for n, s in snapshot_summary.items()
            }
            total_ecn_marked = sum(ecn_marked_per_node.values())
        st.log(f"ECN marked packets per node: {ecn_marked_per_node}")
        st.log(f"Total ECN marked packets: {total_ecn_marked}")

        # Get ECN marking nodes for this congestion point.
        # Prefer derivation from topology role (works for any node naming);
        # fall back to the legacy static map if topology is empty.
        marking_role = CONGESTION_TO_MARKING_ROLE.get(congestion_point)
        if data.topology and marking_role:
            marking_nodes = qos_utils.nodes_by_role(data.topology, marking_role)
            if not marking_nodes:
                marking_nodes = ECN_MARKING_NODES.get(congestion_point, [])
        else:
            marking_nodes = ECN_MARKING_NODES.get(congestion_point, [])
        st.log(f"Expected marking nodes for {congestion_point} "
               f"(role={marking_role}): {marking_nodes}")
        bundle['marking_role'] = marking_role
        bundle['marking_nodes'] = list(marking_nodes)
        bundle['ecn_marked_per_node'] = dict(ecn_marked_per_node)
        bundle['total_ecn_marked'] = int(total_ecn_marked)

        # ECN counter criteria based on ECT value
        # Note: On laguna (G200) and carib (Q200) the ECN-marked counter is
        # incremented even for CE traffic. Detect that case via marking-node
        # platform tags so the CE check can require >0 marks at marking nodes.
        marking_node_platforms = [data.node_meta.get(n, {}).get('platform_type', 'generic') for n in marking_nodes]
        bundle['marking_node_platforms'] = list(marking_node_platforms)

        # ECN counter and packet capture summary -- informational logging only.
        # Validators (validate_ecn_marking) judge ECN counter correctness.
        marking_node_ecn = sum(ecn_marked_per_node.get(n, 0) for n in marking_nodes)
        st.log(f"ECN counter summary: marking_nodes={marking_nodes} "
               f"marking_node_ecn={marking_node_ecn} total_ecn_marked={total_ecn_marked} "
               f"marking_node_platforms={marking_node_platforms}")

        ce_packets = 0
        total_analyzed = 0
        if capture_results and 'T1D4P1' in capture_results:
            cap_data = capture_results['T1D4P1']
            total_analyzed = cap_data.get('analyzed_frames', 0)
            ecn_counts = cap_data.get('ecn_counts', {})
            ce_packets = ecn_counts.get(3, 0)  # CE = 0b11 = 3
            not_ect_packets = ecn_counts.get(0, 0)
            ect1_packets = ecn_counts.get(1, 0)
            ect0_packets = ecn_counts.get(2, 0)
            st.log(f"Packet capture: analyzed={total_analyzed}, Not-ECT={not_ect_packets}, "
                   f"ECT(1)={ect1_packets}, ECT(0)={ect0_packets}, CE={ce_packets}")
        else:
            st.log("Packet capture: No capture results available")

        # Log summary
        platform_name = qos_utils.get_dut_platform(nodes['leaf0']) or "unknown"
        st.banner(f"SUMMARY: {test_name} (Platform: {platform_name})")
        st.log(f"  Congestion point: {congestion_point}")
        st.log(f"  ECN disabled on: {ecn_disable_nodes}")
        st.log(f"  ECT bits: {ect:#04b} ({['Not-ECT', 'ECT(1)', 'ECT(0)', 'CE'][ect]})")
        st.log(f"  TX frames: {tx_frames}")
        st.log(f"  RX frames: {rx_frames}")
        st.log(f"  Loss rate: {loss_rate:.2f}%")
        st.log(f"  PFC XOFF delta ({pfc_xoff_nodes}): {congestion_pfc_delta}")
        st.log(f"  Total ECN marked packets (from WRED counters): {total_ecn_marked}")
        st.log(f"  ECN marked per node: {ecn_marked_per_node}")
        st.log(f"  Packet capture CE packets: {ce_packets}/{total_analyzed}")
        st.log(f"  Runner result: PASS (data verdicts emitted by validator umbrella tests)")

        # Dump running configuration on the requested nodes for post-mortem
        st.banner("Saving running configuration on all nodes")
        for node_name in save_config_nodes:
            if node_name in nodes:
                st.log(f"Saving config on {node_name} to /tmp/ap.json")
                st.config(nodes[node_name], "config save -y /tmp/ap.json")

        # Dump VXLAN tunnel counters on leaf devices
        st.banner("Dumping VXLAN tunnel counters on leaf devices")
        for node_name in ['leaf0', 'leaf1']:
            if node_name in nodes:
                st.config(nodes[node_name], "show vxlan counters")

    except Exception as e:
        st.error(f"Exception in {test_name}: {str(e)}")
        import traceback
        st.error(traceback.format_exc())
        bundle['exception'] = str(e)
        bundle['reason'] = f"exception: {e}"
        bundle['passed'] = False

    finally:
        # Cleanup: Remove streams
        if streams:
            for key, item in streams.items():
                try:
                    tg.tg_traffic_config(mode='remove', stream_id=item['stream_id'])
                except Exception:
                    pass
        if xoff_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
            except Exception:
                pass

        # Cleanup: Stop protocols and destroy NGPF interfaces (use tg_interface_config to clear cache)
        if handles:
            try:
                st.log("Cleaning up NGPF device groups...")
                tg.tg_test_control(action='stop_all_protocols')
                st.wait(2)
                for port_name, handle_dict in handles.items():
                    port_handle = handle_dict.get('port_handle')
                    int_handle = handle_dict.get('int_handle')
                    if port_handle and int_handle:
                        try:
                            tg.tg_interface_config(port_handle=port_handle, handle=int_handle, mode='destroy')
                            st.log(f"Destroyed interface for {port_name}")
                        except Exception as e:
                            st.log(f"Warning: Failed to destroy interface for {port_name}: {e}")
            except Exception as e:
                st.log(f"Warning: NGPF cleanup error: {e}")

        # Restore ECN on non-target nodes
        if saved_ecn_state:
            qos_utils.restore_ecn_on_nodes(nodes, saved_ecn_state)

    return bundle
