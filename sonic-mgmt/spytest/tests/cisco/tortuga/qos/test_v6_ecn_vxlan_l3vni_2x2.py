"""
ECN Marking Accuracy Test over L3VNI with PFC XOFF Backpressure

Simplified ECN test that uses PFC XOFF frames from the egress TGEN to create
backpressure-induced congestion (instead of traffic oversubscription).

Unlike L2VNI where traffic is bridged, L3VNI traffic is routed through
VRF/L3VNI via different subnets on each leaf.

Topology: 2x Spine + 2 Leafs
    SD1 -- Spine0   - D1
    SD2 -- Spine1   - D2
    SD3 -- Leaf0    - D3 (ingress leaf)
    SD4 -- Leaf1    - D4 (egress leaf)

Traffic Path (L3 Routed via VRF):
    T1D3P1 (data 99%) --> Leaf0 (Vrf01/VLAN 2) --> VXLAN --> Leaf1 (Vrf01/VLAN 3) <-- T1D4P1 (XOFF)

Congestion Mechanism:
    1. T1D4P1 sends continuous PFC XOFF frames for TC3 to pause Leaf1's egress
    2. Backpressure propagates: Leaf1 -> Spine0 -> Leaf0
    3. Congestion builds at each hop, triggering ECN CE marking

Congestion Points Tested:
    A. Ingress leaf egress (Leaf0 -> Spine0/1) - ECN disabled on spine0, spine1, leaf1
    B. Spine egress (Spine0/1 -> Leaf1)        - ECN disabled on leaf0, leaf1
    C. Egress leaf TGEN (Leaf1 -> T1D4P1)      - ECN disabled on leaf0, spine0, spine1

ECN Verification:
    - Pass criteria: Traffic flows and ECN counters match expected behavior

"""

import os
import yaml
import pytest
from spytest import st, tgapi, SpyTestDict
import tests.cisco.tortuga.vxlan.vxlan_utils as vxlan_obj
import traffic_stream_ixia_api as stream_api
import qos_test_utils as qos_utils
import gamut_qos_utils as gamut_utils

CONFIGS_FILE = '../qos/vxlan_ecn_l3vni_2x1.yaml'

data = SpyTestDict()

# L3VNI uses different subnets on each leaf (routed traffic)
# Ingress TGEN port on leaf0 (VLAN 2 / 2002:db8:1::/64)
data.t1d3p1_ip6_addr = "2002:db8:1::2"
data.t1d3p1_mac_addr = "00:0a:01:00:11:01"
data.d3t1_ip6_addr = "2002:db8:1::1"  # Gateway on leaf0 Vlan2

# Egress TGEN port on leaf1 (VLAN 3 / 2003:db8:1::/64)
data.t1d4p1_ip6_addr = "2003:db8:1::2"
data.t1d4p1_mac_addr = "00:0a:01:00:12:01"
data.d4t1_ip6_addr = "2003:db8:1::1"  # Gateway on leaf1 Vlan3

# Traffic parameters
data.traffic_run_time = 60
data.tc = 3  # Traffic Class for PFC-enabled lossless queue
data.frame_size = "1350"
data.rate_percent = "99"
data.vlan_id = "2"  # Ingress VLAN on leaf0
data.mask = "64"
data.addr_family = 'ipv6'
data.capture_count=100

# VTEP IPs for L3VNI topology
LEAF0_VTEP_IP = '2001:db8:1::2'
LEAF1_VTEP_IP = '2001:db8:1::3'

# ECN/ECT constants
ECN_NOT_ECT = 0b00
ECN_ECT_01 = 0b01
ECN_ECT_10 = 0b10
ECN_CE = 0b11

# Map congestion point to nodes where ECN marking should occur
# (i.e., the target nodes that have ECN enabled)
ECN_MARKING_NODES = {
    'ingress_leaf_egress': ['leaf0'],           # ECN enabled only on leaf0
    'spine_egress':        ['spine0', 'spine1'], # ECN enabled on both spines
    'egress_leaf_tgen':    ['leaf1'],           # ECN enabled only on leaf1
}

# Map congestion point to nodes where PFC XOFF should be received
# (i.e., the node at the congestion point receives XOFF from downstream)
PFC_XOFF_NODES = {
    'ingress_leaf_egress': ['leaf0'],           # leaf0 receives XOFF from spines
    'spine_egress':        ['spine0', 'spine1'], # spines receive XOFF from leaf1
    'egress_leaf_tgen':    ['leaf1'],           # leaf1 receives XOFF from TGEN
}

# Module-level state
updated_config_file = None
port_speed_gbps = None
topo_info = None
platform_type = None  # 'n9164e' for Gamut, 'hf6100' for HF6100, 'generic' otherwise


def get_nodes():
    """Get node mapping using shared utility."""
    return qos_utils.get_nodes()


def config_node(node, config, type='', skip_errors=False):
    if type:
        st.config(node, config, type=type, skip_error_check=skip_errors, conf=True)
    else:
        st.config(node, config, skip_error_check=skip_errors, conf=True)


def config_static(node, config_domain, add=True):
    """Configure or deconfigure static configs from YAML template."""
    nodes = get_nodes()
    domain = 'vtysh' if config_domain == 'bgp' else ''

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
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


def setup_tgen_interfaces_and_stream(tc, rate_percent, ect=ECN_ECT_10):
    """
    Configure TGEN interfaces and create a single data stream from T1D3P1 to T1D4P1.

    Uses vxlan_obj helpers to properly set up NGPF topologies with IPv6 stacks
    and verify connectivity via ping before creating traffic.

    Args:
        tc: Traffic class for DSCP mapping
        rate_percent: Rate as percentage of line rate
        ect: ECN codepoint (default ECT(0))

    Returns:
        tuple: (streams_dict, handles, int_dict)
            - streams_dict: Traffic stream dictionary from config_traffic_item
            - handles: TGEN handles from config_tgen_interface
            - int_dict: Interface dictionary used for configuration
    """
    nodes = get_nodes()

    # Get DSCP value for the target TC
    dscp = qos_utils.convert_tc_to_dscp(nodes['leaf0'], tc)
    st.log(f"Using DSCP {dscp} for TC {tc}, ECT={ect}")

    # Configure TGEN interfaces - source and destination only
    # Note: L3VNI uses different subnets on each leaf
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


def dump_l3vni_diagnostics(nodes, phase=""):
    """
    Dump L3VNI state for debugging - VRF routes, EVPN, VXLAN status.
    """
    st.banner(f"{phase} L3VNI DIAGNOSTICS")
    for node_name in ['leaf0', 'leaf1']:
        dut = nodes[node_name]
        st.log(f"--- {node_name} ---")
        # Check VRF routes
        st.log(f"{node_name}: show ipv6 route vrf Vrf01")
        st.config(dut, "vtysh -c 'show ipv6 route vrf Vrf01'", skip_error_check=True)
        # Check EVPN Type-5 routes
        st.log(f"{node_name}: show bgp l2vpn evpn route type prefix")
        st.config(dut, "vtysh -c 'show bgp l2vpn evpn route type prefix'", skip_error_check=True)
        # Check EVPN VNI
        st.log(f"{node_name}: show evpn vni 1000")
        st.config(dut, "vtysh -c 'show evpn vni 1000'", skip_error_check=True)
        # Check remote VTEP status
        st.log(f"{node_name}: show vxlan remotevtep")
        st.show(dut, "show vxlan remotevtep", skip_tmpl=True, skip_error_check=True)


def verify_l3vni_asic_entries(nodes):
    """
    Verify L3VNI ASIC programming (VNI-to-VRF mapping).
    
    Returns True if entries are present, False otherwise.
    """
    leaf_vlan = {'leaf0': '2', 'leaf1': '3'}
    all_good = True
    
    for node_name in ['leaf0', 'leaf1']:
        dut = nodes[node_name]
        vlan_id = leaf_vlan[node_name]
        
        # Check ASIC_DB for VNI_TO_VIRTUAL_ROUTER_ID entries
        output = st.config(dut,
            "sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY:*'",
            skip_error_check=True)
        has_vrf_entry = False
        entry_keys = [line.strip() for line in output.split('\n')
                      if line.strip().startswith('ASIC_STATE:')]
        for key in entry_keys:
            val = st.config(dut,
                f"sonic-db-cli ASIC_DB HGETALL '{key}'",
                skip_error_check=True)
            if 'VIRTUAL_ROUTER' in val:
                has_vrf_entry = True
                break
        
        if has_vrf_entry:
            st.log(f"{node_name}: L3VNI ASIC entries confirmed present")
        else:
            st.log(f"WARNING: {node_name}: L3VNI ASIC entries MISSING - attempting recovery...")
            # Remove and re-add VRF-VNI mapping
            st.config(dut, f"sudo config vxlan map del VXLAN {vlan_id} 1000",
                      skip_error_check=True)
            st.config(dut, "sudo config vrf del_vrf_vni_map Vrf01",
                      skip_error_check=True)
            st.wait(5)
            st.config(dut, "sudo config vrf add_vrf_vni_map Vrf01 1000",
                      skip_error_check=True)
            st.wait(5)
            st.config(dut, f"sudo config vxlan map add VXLAN {vlan_id} 1000",
                      skip_error_check=True)
            st.wait(5)
            all_good = False
    
    return all_good


def run_ecn_xoff_test(congestion_point, test_name, ect=ECN_ECT_10):
    """
    Generic ECN test runner using PFC XOFF backpressure.

    Args:
        congestion_point: One of 'ingress_leaf_egress', 'spine_egress', 'egress_leaf_tgen'
        test_name: Name for logging/reporting
        ect: ECT bits to use in traffic (default ECT(0))

    Returns:
        bool: True if test passed
    """
    global port_speed_gbps, topo_info, platform_type
    vars = st.get_testbed_vars()
    nodes = get_nodes()

    streams = None
    handles = None
    xoff_stream_id = None
    saved_ecn_state = {}
    result = False
    capture_started = False
    wred_before = {}
    wred_after = {}
    wred_summary = {}
    watermarks = {}

    # Define interfaces for WRED counter capture on all 4 nodes
    # With XOFF-based congestion, we only need 1 port per leaf-spine link
    wred_interfaces = {
        'leaf0': [vars.D3D1P1] + ([vars.D3D2P1] if hasattr(vars, 'D3D2P1') else []),
        'spine0': [vars.D1D4P1] if hasattr(vars, 'D1D4P1') else [],
        'spine1': [vars.D2D4P1] if hasattr(vars, 'D2D4P1') else [],
        'leaf1': [vars.D4T1P1]
    }
    st.log(f"WRED interfaces for counter capture: {wred_interfaces}")

    try:
        # Pre-test: Verify L3VNI ASIC entries
        st.banner("Verifying L3VNI ASIC entries before test")
        verify_l3vni_asic_entries(nodes)

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
        xoff_rate = get_xoff_rate(port_speed_gbps)
        st.banner(f"Creating PFC XOFF stream FIRST: T1D4P1 at {xoff_rate} fps for TC3 (BEFORE NGPF)")
        xoff_stream_id = qos_utils.create_pfc_xoff_stream(
            tg_dst, 'T1D4P1', data.t1d4p1_mac_addr, xoff_rate
        )

        # Apply PFC stream immediately to lock in the L2 header
        st.banner("Applying PFC stream configuration to lock in L2 header")
        tg_dst.tg_traffic_control(action='apply')
        st.wait(1)

        # Step 3a: Verify L3VNI routing state BEFORE NGPF setup (debug ping failures)
        st.banner("PRE-PING: Verifying L3VNI routing and VXLAN state")
        for node_name in ['leaf0', 'leaf1']:
            dut = nodes[node_name]
            st.log(f"--- {node_name}: show ipv6 route vrf Vrf01 ---")
            st.config(dut, "vtysh -c 'show ipv6 route vrf Vrf01'", skip_error_check=True)
            st.log(f"--- {node_name}: show vxlan remotevtep ---")
            st.config(dut, "show vxlan remotevtep", skip_error_check=True)
            st.log(f"--- {node_name}: show bgp l2vpn evpn summary ---")
            st.config(dut, "vtysh -c 'show bgp l2vpn evpn summary'", skip_error_check=True)
            st.log(f"--- {node_name}: show bgp l2vpn evpn route type prefix ---")
            st.config(dut, "vtysh -c 'show bgp l2vpn evpn route type prefix'", skip_error_check=True)
            st.log(f"--- {node_name}: show vlan brief ---")
            st.config(dut, "show vlan brief", skip_error_check=True)
            st.log(f"--- {node_name}: show mac address-table ---")
            st.config(dut, "show mac", skip_error_check=True)
            st.log(f"--- {node_name}: show vxlan vlanvnimap ---")
            st.config(dut, "show vxlan vlanvnimap", skip_error_check=True)
            st.log(f"--- {node_name}: show dropcounters counts ---")
            st.config(dut, "show dropcounters counts", skip_error_check=True)
            st.log(f"--- {node_name}: show ipv6 neighbors ---")
            st.config(dut, "show ipv6 neighbors", skip_error_check=True)

        # DUT-to-DUT ping through VRF to verify tunnel data plane
        st.log("--- leaf0: ping leaf1 SVI through Vrf01 ---")
        st.config(nodes['leaf0'], "ping6 -c 3 -I Vrf01 2003:db8:1::1", skip_error_check=True)

        # Step 3: Now set up TGEN interfaces and create data stream using NGPF
        st.banner(f"Setting up TGEN interfaces and data stream at {data.rate_percent}%")
        streams, handles, int_dict = setup_tgen_interfaces_and_stream(
            data.tc, float(data.rate_percent), ect
        )

        # Get the stream_id from the streams dictionary
        stream_key = 'T1D3P1<-->T1D4P1'
        data_stream_id = streams[stream_key]['stream_id']
        st.log(f"Data stream created: {stream_key} -> {data_stream_id}")

        # Pre-traffic diagnostics
        dump_l3vni_diagnostics(nodes, "PRE-TRAFFIC")

        # Step 4: Clear all DUT counters and watermarks before traffic
        st.banner("Clearing all DUT counters and watermarks")
        for dut in st.get_dut_names():
            qos_utils.clear_all_counters(dut)

        # Clear Gamut-specific port counters on n9164e (Gamut) nodes
        for node_name, dut in nodes.items():
            if qos_utils.detect_platform(dut) == 'n9164e':
                st.log(f"Clearing Gamut port counters on {node_name}")
                gamut_utils.gamut_clear_port_counters(dut)

        # Step 5: Clear and capture WRED/ECN counters BEFORE traffic
        st.banner("Clearing WRED/ECN counters on all nodes")
        qos_utils.clear_all_wred_counters(nodes, wred_interfaces, tc=data.tc)

        # Clear queue watermarks on all nodes (with robust verification)
        st.banner("Clearing queue watermarks on all nodes")
        qos_utils.clear_all_queue_watermarks(nodes, wait_after=3)

        st.banner("Capturing WRED/ECN counters BEFORE traffic")
        wred_before = qos_utils.capture_wred_counters(nodes, wred_interfaces, tc=data.tc)

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
        st.wait(5)

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

        if congestion_pfc_delta <= 0:
            st.error(f"PFC XOFF not received at congestion point {pfc_xoff_nodes}! Expected delta > 0, got {congestion_pfc_delta}")

        # Step 14: Get traffic statistics (TX and RX counts)
        # Try traffic_item mode first, then DUT counters as fallback
        st.banner("Reading traffic statistics")
        st.log(f"src_port_handle={src_port_handle}, dst_port_handle={dst_port_handle}, data_stream_id={data_stream_id}")

        tx_frames = 0
        rx_frames = 0

        # Method 1: Try traffic_item mode (more reliable for stream-based stats)
        '''
        TODO: FIXME This is timing out after like 300 seconds on IxNetwork side - need to investigate if it's a bug or if we need to wait longer after stopping traffic before stats are available
        try:
            st.log("Trying mode='traffic_item' for traffic stats...")
            ti_stats = tg.tg_traffic_stats(mode='traffic_item')
            if ti_stats.get('status') == '1' and 'traffic_item' in ti_stats:
                # Look for our stream in traffic_item stats
                for ti_key, ti_val in ti_stats['traffic_item'].items():
                    if ti_key == 'aggregate':
                        continue
                    tx_info = ti_val.get('tx', {})
                    rx_info = ti_val.get('rx', {})
                    tx_frames = int(tx_info.get('total_pkts', 0) or 0)
                    rx_frames = int(rx_info.get('total_pkts', 0) or 0)
                    if tx_frames > 0 or rx_frames > 0:
                        st.log(f"traffic_item stats: {ti_key} TX={tx_frames}, RX={rx_frames}")
                        break
        except Exception as e:
            st.log(f"traffic_item stats failed: {e}")
        '''

        # Method 2: Fallback to DUT interface counters if TGEN stats failed
        # The TGEN-facing ports on leaf0/leaf1 give us TX/RX approximation
        stats_from_dut = False
        if tx_frames == 0 and rx_frames == 0:
            st.log("TGEN stats unavailable - using DUT interface counters as fallback")
            stats_from_dut = True
            try:
                # TX: leaf0 TGEN port RX counter (packets received from TGEN into leaf0)
                tx_output = st.show(nodes['leaf0'], f"show interface counters | grep {vars.D3T1P1}",
                                   skip_tmpl=True, skip_error_check=True)
                # RX: leaf1 TGEN port TX counter (packets sent from leaf1 to TGEN)
                rx_output = st.show(nodes['leaf1'], f"show interface counters | grep {vars.D4T1P1}",
                                   skip_tmpl=True, skip_error_check=True)
                # Parse counters - format: IFACE STATE RX_OK RX_BPS RX_UTIL ... TX_OK TX_BPS ...
                import re
                # RX_OK is the first large number after interface name
                tx_match = re.search(r'U\s+([\d,]+)\s+', tx_output)
                # TX_OK is after a series of RX columns - look for pattern after U
                # Typical format: Ethernet1_58_1  U  760,017,886  0.00 B/s  0.00%  0  0  0  33  8.17 B/s
                # We need the first number (RX_OK)
                rx_full_match = re.search(r'U\s+([\d,]+)\s+[\d.]+\s+B/s\s+[\d.]+%\s+\d+\s+\d+\s+\d+\s+([\d,]+)', rx_output)
                if tx_match:
                    tx_frames = int(tx_match.group(1).replace(',', ''))
                if rx_full_match:
                    # For egress port, we want TX_OK which is the second capture group
                    rx_frames = int(rx_full_match.group(2).replace(',', ''))
                st.log(f"DUT-based stats: TX~={tx_frames}, RX~={rx_frames}")
            except Exception as dut_err:
                st.error(f"DUT counter fallback also failed: {dut_err}")

        st.log(f"Traffic stats: TX={tx_frames}, RX={rx_frames} (from_dut={stats_from_dut})")

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

        # Step 15: Determine pass/fail with ECN-specific criteria
        basic_pass = rx_frames > 0
        if not basic_pass:
            st.error(f"FAIL: No traffic received (TX={tx_frames}, RX={rx_frames})")
            dump_l3vni_diagnostics(nodes, "POST-TRAFFIC FAILURE")
            result = False
        else:
            st.log(f"Basic traffic check PASS: TX={tx_frames}, RX={rx_frames}")
            if congestion_pfc_delta > 0:
                st.log(f"PFC XOFF received at congestion point (delta={congestion_pfc_delta})")
            else:
                st.log(f"WARNING: PFC XOFF not received at congestion point (delta={congestion_pfc_delta})")
            result = True

        # Compute ECN marked packets per node from WRED summary
        ecn_marked_per_node = {}
        total_ecn_marked = 0
        for node_name, interfaces in (wred_summary or {}).items():
            node_ecn_marked = 0
            for intf, counters in interfaces.items():
                node_ecn_marked += counters.get('ecn_marked_pkts', 0)
            ecn_marked_per_node[node_name] = node_ecn_marked
            total_ecn_marked += node_ecn_marked
        st.log(f"ECN marked packets per node: {ecn_marked_per_node}")
        st.log(f"Total ECN marked packets: {total_ecn_marked}")

        # Get ECN marking nodes for this congestion point
        marking_nodes = ECN_MARKING_NODES.get(congestion_point, [])
        st.log(f"Expected marking nodes for {congestion_point}: {marking_nodes}")

        # ECN counter criteria based on ECT value
        # Note: On HF6100 platforms, ECN marked counter is incremented even for CE traffic
        ecn_counter_pass = True
        if ect in (ECN_ECT_01, ECN_ECT_10):
            marking_node_ecn = sum(ecn_marked_per_node.get(n, 0) for n in marking_nodes)
            if marking_node_ecn > 0:
                st.log(f"ECN counter check PASS: Marking nodes {marking_nodes} have {marking_node_ecn} ECN marked packets")
            else:
                st.error(f"ECN counter check FAIL: Marking nodes {marking_nodes} have 0 ECN marked packets (expected > 0)")
                ecn_counter_pass = False
        elif ect == ECN_CE and platform_type == 'hf6100':
            # HF6100: CE traffic still increments ECN marked counter at congestion points
            marking_node_ecn = sum(ecn_marked_per_node.get(n, 0) for n in marking_nodes)
            if marking_node_ecn > 0:
                st.log(f"ECN counter check PASS (HF6100): Marking nodes {marking_nodes} have {marking_node_ecn} ECN marked packets for CE traffic")
            else:
                st.error(f"ECN counter check FAIL (HF6100): Marking nodes {marking_nodes} have 0 ECN marked packets for CE traffic (expected > 0)")
                ecn_counter_pass = False
        elif ect == ECN_NOT_ECT:
            # Not-ECT: NO node should have ECN counters incremented
            if total_ecn_marked == 0:
                st.log(f"ECN counter check PASS: No ECN marking (total=0) for Not-ECT traffic")
            else:
                st.error(f"ECN counter check FAIL: Unexpected ECN marking (total={total_ecn_marked}) for Not-ECT traffic")
                ecn_counter_pass = False
        elif ect == ECN_CE:
            # Non-HF6100 platforms: CE traffic should NOT increment ECN counters
            if total_ecn_marked == 0:
                st.log(f"ECN counter check PASS: No ECN marking (total=0) for CE traffic")
            else:
                st.error(f"ECN counter check FAIL: Unexpected ECN marking (total={total_ecn_marked}) for CE traffic")
                ecn_counter_pass = False

        # Packet capture criteria (informational)
        capture_pass = True
        ce_packets = 0
        total_analyzed = 0
        if capture_results and 'T1D4P1' in capture_results:
            cap_data = capture_results['T1D4P1']
            total_analyzed = cap_data.get('analyzed_frames', 0)
            ecn_counts = cap_data.get('ecn_counts', {})
            ce_packets = ecn_counts.get(3, 0)
            not_ect_packets = ecn_counts.get(0, 0)
            ect1_packets = ecn_counts.get(1, 0)
            ect0_packets = ecn_counts.get(2, 0)
            st.log(f"Packet capture: analyzed={total_analyzed}, Not-ECT={not_ect_packets}, ECT(1)={ect1_packets}, ECT(0)={ect0_packets}, CE={ce_packets}")

            if ect in (ECN_ECT_01, ECN_ECT_10):
                if ce_packets > 0:
                    ce_pct = (ce_packets / total_analyzed * 100) if total_analyzed > 0 else 0
                    st.log(f"Packet capture check PASS: {ce_packets} CE packets ({ce_pct:.1f}%)")
                else:
                    st.error(f"Packet capture check FAIL: 0 CE packets in capture (expected > 0)")
                    capture_pass = False
            elif ect == ECN_NOT_ECT:
                if ce_packets == 0:
                    st.log(f"Packet capture check PASS: 0 CE packets (Not-ECT traffic not marked)")
                else:
                    st.error(f"Packet capture check FAIL: {ce_packets} CE packets (Not-ECT should not be marked)")
                    capture_pass = False
            elif ect == ECN_CE:
                if total_analyzed > 0 and ce_packets >= total_analyzed * 0.9:
                    st.log(f"Packet capture check PASS: {ce_packets}/{total_analyzed} CE packets (CE traffic preserved)")
                elif ce_packets > 0:
                    st.log(f"Packet capture check INFO: {ce_packets}/{total_analyzed} CE packets")
                else:
                    st.log(f"Packet capture check WARNING: 0 CE packets but sent CE traffic")
        else:
            st.log("Packet capture: No capture results available (skipping capture validation)")

        # Final result: basic_pass and ecn_counter_pass determine pass/fail
        if basic_pass and ecn_counter_pass:
            result = True
        else:
            result = False

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
        st.log(f"  Criteria: basic_pass={basic_pass}, ecn_counter_pass={ecn_counter_pass}, capture_pass={capture_pass} (informational)")
        st.log(f"  Result: {'PASS' if result else 'FAIL'}")

        # Dump running configuration on all nodes for post-mortem analysis
        st.banner("Saving running configuration on all nodes")
        for node_name in ['leaf0', 'leaf1', 'spine0', 'spine1']:
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
        result = False

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

        # Cleanup: Stop protocols and destroy NGPF device groups to avoid duplicate IP/MAC
        if handles:
            try:
                st.log("Cleaning up NGPF device groups...")
                tg.tg_test_control(action='stop_all_protocols')
                st.wait(2)
                for port_name, handle_dict in handles.items():
                    if 'topology_handle' in handle_dict:
                        try:
                            tg.tg_topology_config(topology_handle=handle_dict['topology_handle'], mode='destroy')
                            st.log(f"Destroyed topology for {port_name}")
                        except Exception as e:
                            st.log(f"Warning: Failed to destroy topology for {port_name}: {e}")
            except Exception as e:
                st.log(f"Warning: NGPF cleanup error: {e}")

        # Restore ECN on non-target nodes
        if saved_ecn_state:
            qos_utils.restore_ecn_on_nodes(nodes, saved_ecn_state)

    return result


@pytest.fixture(scope="module", autouse=True)
def module_setup():
    """
    Module-level setup for ECN XOFF tests over L3VNI.

    Steps:
        1. Initialize QoS (does config reload on Gamut - must be FIRST)
        2. Clean up any existing config
        3. Apply VXLAN/BGP config for L3VNI
        4. Wait for BGP EVPN convergence
        5. Verify L3VNI ASIC programming
        6. Get port speed for XOFF rate calculation
        7. Validate testbed topology
        8. Verify ECN enabled
        9. Detect platform type
    """
    global updated_config_file, port_speed_gbps, topo_info, platform_type

    vars = st.get_testbed_vars()
    nodes = get_nodes()

    # ---- Speed up queue watermark counterpoll (default 60s is too slow) ----
    for dut in st.get_dut_names():
        qos_utils.set_queue_watermark_poll_interval(dut, 1000)

    # ---- Enable WRED queue counterpoll for ECN/WRED counter visibility ----
    st.log("Enabling wredqueue counterpoll")
    for dut in st.get_dut_names():
        st.config(dut, "sudo counterpoll wredqueue enable", skip_error_check=True)

    # Step 1: Clean up any existing config
    st.banner("STEP 1: Cleaning up any existing VXLAN/BGP configuration")
    for node_name in ['leaf0', 'leaf1']:
        dut = nodes[node_name]
        qos_utils.cleanup_config(dut)

    # Remove any leftover VRF BGP instances
    #qos_utils.cleanup_leftover_vrf_bgp(nodes)
   
    # Step 2: Initialize QoS (MUST be first - does config reload on Gamut which wipes runtime config)
    st.banner("STEP 2: Initializing QoS configuration (before VXLAN/BGP setup)")
    for dut in st.get_dut_names():
        stream_api.init_qos_on_dut(dut)
        qos_utils.load_config_db(dut)

    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE, vars)

    # Deconfigure first (cleanup)
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node in reversed(list(config_list.keys())):
            config_static(node, 'bgp', add=False)
            st.wait(1)
            config_static(node, 'sonic', add=False)

    st.wait(5)

    # Step 3: Apply VXLAN/BGP configuration for L3VNI
    st.banner("STEP 3: Applying L3VNI VXLAN/BGP configuration from template")
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)

        # Phase 1: Apply SONiC/VXLAN configs
        st.log("Phase 1: Applying SONiC/VXLAN configuration...")
        for node in config_list.keys():
            config_static(node, 'sonic')

        # Enable tunnel counterpoll on leaves
        for node_name in ['leaf0', 'leaf1']:
            st.config(nodes[node_name], "sudo counterpoll tunnel enable", skip_error_check=True)

        st.wait(5)

        # Phase 2: Apply BGP configs
        st.log("Phase 2: Applying BGP configuration...")
        for node in config_list.keys():
            config_static(node, 'bgp')

        # Save BGP config
        for node in config_list.keys():
            st.config(nodes[node], "vtysh -c 'write memory'", skip_error_check=True)

    # Wait for VNI to register
    st.log("Waiting for VNI to register in zebra...")
    st.wait(30)

    # Step 4: Wait for BGP EVPN convergence
    st.banner("STEP 4: Waiting for BGP EVPN convergence")
    if not qos_utils.wait_for_bgp_evpn_established(nodes, max_wait=180):
        st.log("WARNING: BGP EVPN sessions may not be fully established")

    # Wait for VXLAN tunnels
    st.banner("Waiting for VXLAN tunnels to establish")
    for node_name in ['leaf0', 'leaf1']:
        dut = nodes[node_name]
        for attempt in range(12):
            output = st.config(dut, "show vxlan remotevtep")
            if 'oper_up' in output or '2001:db8:1::' in output:
                st.log(f"{node_name}: VXLAN tunnel UP")
                break
            st.log(f"{node_name}: Waiting for VXLAN tunnel... attempt {attempt + 1}/12")
            st.wait(10)

    # DUMP full connectivity and BGP session details for debugging
    qos_utils.dump_vxlan_debug_info(nodes, "BGP session details")

    # Step 5: Verify L3VNI ASIC programming
    st.banner("STEP 5: Verifying L3VNI ASIC programming")
    verify_l3vni_asic_entries(nodes)

    # Step 6: Get port speed for XOFF rate calculation
    st.banner("STEP 6: Getting port speed for XOFF rate calculation")
    speeds = qos_utils.get_link_speeds(nodes, {'leaf1': [vars.D4T1P1]})
    port_speed_gbps = speeds['leaf1'][vars.D4T1P1]
    st.log(f"Port speed: {port_speed_gbps} Gbps, XOFF rate will be {get_xoff_rate(port_speed_gbps)} fps")

    # Step 7: Validate testbed topology
    st.banner("STEP 7: Validating ECN testbed topology for WRED counter interfaces")
    topo_info = qos_utils.validate_ecn_testbed_topology()
    if not topo_info['valid']:
        st.log(f"WARNING: Testbed topology validation issue: {topo_info.get('error')}")
        st.log("Continuing with minimal port set for WRED counters...")

    # Step 8: Verify ECN configuration
    st.banner("STEP 8: Verifying ECN configuration")
    qos_utils.verify_ecn_config(nodes, ['leaf0', 'leaf1', 'spine0', 'spine1'])

    # Step 9: Detect platform type
    st.banner("STEP 9: Detecting platform type")
    platform_type = qos_utils.detect_platform(nodes['leaf0'])
    st.log(f"Detected platform type: {platform_type}")

    '''
    if platform_type == 'n9164e':
        st.banner("Gamut platform detected - Building port mappings for all nodes")
        for node_name, dut in nodes.items():
            st.log(f"Building Gamut port mapping for {node_name}...")
            gamut_utils.gamut_build_port_mapping(dut)
    '''

    yield

    # Module cleanup
    st.banner("MODULE CLEANUP: Removing VXLAN/BGP configuration")
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node in reversed(list(config_list.keys())):
            config_static(node, 'bgp', add=False)
            st.wait(1)
            config_static(node, 'sonic', add=False)

    vxlan_obj.remove_temp_config(updated_config_file)


# =============================================================================
# Helper to run a test and report pass/fail
# =============================================================================

def _run_and_report(banner_text, congestion_point, test_name, ect=ECN_ECT_10):
    st.banner(banner_text)
    result = run_ecn_xoff_test(congestion_point, test_name, ect=ect)
    if result:
        st.report_pass("test_case_passed", f"{test_name} passed")
    else:
        st.report_fail("test_case_failed", f"{test_name} failed")


# =============================================================================
# ECN Test Cases - ECT(10) at 3 Congestion Points
# =============================================================================

def test_ecn_l3vni_ect10_ingress_leaf_egress():
    """
    Test ECN marking at ingress leaf egress (Leaf0 -> Spine0/1).

    ECN disabled on: spine0, spine1, leaf1
    ECN marking expected at: leaf0
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Ingress Leaf Egress ECT(10) (Leaf0 -> Spine0/1)",
        'ingress_leaf_egress',
        "test_ecn_l3vni_ect10_ingress_leaf_egress",
        ect=ECN_ECT_10
    )


def test_ecn_l3vni_ect10_spine_egress():
    """
    Test ECN marking at spine egress (Spine0/1 -> Leaf1).

    ECN disabled on: leaf0, leaf1
    ECN marking expected at: spine0, spine1
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Spine Egress ECT(10) (Spine0/1 -> Leaf1)",
        'spine_egress',
        "test_ecn_l3vni_ect10_spine_egress",
        ect=ECN_ECT_10
    )


def test_ecn_l3vni_ect10_egress_leaf_tgen():
    """
    Test ECN marking at egress leaf TGEN port (Leaf1 -> T1D4P1).

    ECN disabled on: leaf0, spine0, spine1
    ECN marking expected at: leaf1
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Egress Leaf TGEN ECT(10) (Leaf1 -> T1D4P1)",
        'egress_leaf_tgen',
        "test_ecn_l3vni_ect10_egress_leaf_tgen",
        ect=ECN_ECT_10
    )


# =============================================================================
# ECN Test Cases - ECT(01) at 3 Congestion Points
# =============================================================================

def test_ecn_l3vni_ect01_ingress_leaf_egress():
    """
    Test ECN marking at ingress leaf egress (Leaf0 -> Spine0/1) with ECT(1).

    ECN disabled on: spine0, spine1, leaf1
    ECN marking expected at: leaf0
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Ingress Leaf Egress ECT(01) (Leaf0 -> Spine0/1)",
        'ingress_leaf_egress',
        "test_ecn_l3vni_ect01_ingress_leaf_egress",
        ect=ECN_ECT_01
    )


def test_ecn_l3vni_ect01_spine_egress():
    """
    Test ECN marking at spine egress (Spine0/1 -> Leaf1) with ECT(1).

    ECN disabled on: leaf0, leaf1
    ECN marking expected at: spine0, spine1
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Spine Egress ECT(01) (Spine0/1 -> Leaf1)",
        'spine_egress',
        "test_ecn_l3vni_ect01_spine_egress",
        ect=ECN_ECT_01
    )


def test_ecn_l3vni_ect01_egress_leaf_tgen():
    """
    Test ECN marking at egress leaf TGEN port (Leaf1 -> T1D4P1) with ECT(1).

    ECN disabled on: leaf0, spine0, spine1
    ECN marking expected at: leaf1
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Egress Leaf TGEN ECT(01) (Leaf1 -> T1D4P1)",
        'egress_leaf_tgen',
        "test_ecn_l3vni_ect01_egress_leaf_tgen",
        ect=ECN_ECT_01
    )


# =============================================================================
# ECN Test Cases - Not-ECT (00) at 3 Congestion Points (no marking expected)
# =============================================================================

def test_ecn_l3vni_noect_ingress_leaf_egress():
    """
    Test with Not-ECT at ingress leaf egress (Leaf0 -> Spine0/1).

    ECN disabled on: spine0, spine1, leaf1
    No ECN marking expected (Not-ECT traffic should not be marked)
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Ingress Leaf Egress NotECT (Leaf0 -> Spine0/1)",
        'ingress_leaf_egress',
        "test_ecn_l3vni_noect_ingress_leaf_egress",
        ect=ECN_NOT_ECT
    )


def test_ecn_l3vni_noect_spine_egress():
    """
    Test with Not-ECT at spine egress (Spine0/1 -> Leaf1).

    ECN disabled on: leaf0, leaf1
    No ECN marking expected (Not-ECT traffic should not be marked)
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Spine Egress NotECT (Spine0/1 -> Leaf1)",
        'spine_egress',
        "test_ecn_l3vni_noect_spine_egress",
        ect=ECN_NOT_ECT
    )


def test_ecn_l3vni_noect_egress_leaf_tgen():
    """
    Test with Not-ECT at egress leaf TGEN port (Leaf1 -> T1D4P1).

    ECN disabled on: leaf0, spine0, spine1
    No ECN marking expected (Not-ECT traffic should not be marked)
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Egress Leaf TGEN NotECT (Leaf1 -> T1D4P1)",
        'egress_leaf_tgen',
        "test_ecn_l3vni_noect_egress_leaf_tgen",
        ect=ECN_NOT_ECT
    )


# =============================================================================
# ECN Test Cases - Already CE (11) at 3 Congestion Points (log only, no marking)
# =============================================================================

def test_ecn_l3vni_ce_ingress_leaf_egress():
    """
    Test with CE at ingress leaf egress (Leaf0 -> Spine0/1).

    ECN disabled on: spine0, spine1, leaf1
    Already CE traffic - should remain CE (log only)
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Ingress Leaf Egress CE (Leaf0 -> Spine0/1)",
        'ingress_leaf_egress',
        "test_ecn_l3vni_ce_ingress_leaf_egress",
        ect=ECN_CE
    )


def test_ecn_l3vni_ce_spine_egress():
    """
    Test with CE at spine egress (Spine0/1 -> Leaf1).

    ECN disabled on: leaf0, leaf1
    Already CE traffic - should remain CE (log only)
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Spine Egress CE (Spine0/1 -> Leaf1)",
        'spine_egress',
        "test_ecn_l3vni_ce_spine_egress",
        ect=ECN_CE
    )


def test_ecn_l3vni_ce_egress_leaf_tgen():
    """
    Test with CE at egress leaf TGEN port (Leaf1 -> T1D4P1).

    ECN disabled on: leaf0, spine0, spine1
    Already CE traffic - should remain CE (log only)
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Egress Leaf TGEN CE (Leaf1 -> T1D4P1)",
        'egress_leaf_tgen',
        "test_ecn_l3vni_ce_egress_leaf_tgen",
        ect=ECN_CE
    )
