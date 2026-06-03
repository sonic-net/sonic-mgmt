import time
import json
import os
import sys
import pytest
import pprint
import qos_test_utils as common_util
import qos_test_utils
import traffic_stream_ixia_api as stream_api

from spytest import st, tgapi, SpyTestDict

# Test configuration
TRAFFIC_CLASS = 3
STREAM_FACTOR = 0.95  # 95% line rate
FRAME_SIZE = 1350
TRAFFIC_DURATION = 60  # seconds

# Stream definitions: 2 sources -> 1 destination (2:1 oversubscription)
# Both streams from Leaf0 (D3) converge to single port on Leaf1 (D4)
STREAM_DEFS = [
    ('T1D3P1', 'T1D4P1'),
    ('T1D3P2', 'T1D4P1'),
]


def configure_spine1_only_100g():
    """
    Shutdown Spine2 links and set Spine1 links to 100G.
    This simulates the Jira scenario scaled down:
    - Original: 360G×2 through 400G×2 spines
    - Scaled: 99G×2 through 100G×1 spine
    """
    global vars, test_info
    st.banner("Shutting down Spine2 links and setting Spine1 links to 100G")
    
    # Shutdown Spine2-Leaf links (both ends, all ports)
    spine2_links = [
        (vars.D2, vars.D2D3P1),  # Spine2 to Leaf0 (first link)
        (vars.D2, vars.D2D4P1),  # Spine2 to Leaf1 (first link)
        (vars.D3, vars.D3D2P1),  # Leaf0 to Spine2 (first link)
        (vars.D4, vars.D4D2P1),  # Leaf1 to Spine2 (first link)
    ]
    # Add optional second links if they exist in this testbed
    optional_spine2_links = [
        ('D2', 'D2D3P2', 'D3', 'D3D2P2'),  # Spine2 to Leaf0 (second link)
        ('D2', 'D2D4P2', 'D4', 'D4D2P2'),  # Spine2 to Leaf1 (second link)
    ]
    for d2_name, d2_port, dx_name, dx_port in optional_spine2_links:
        if hasattr(vars, d2_port) and hasattr(vars, dx_port):
            spine2_links.append((getattr(vars, d2_name), getattr(vars, d2_port)))
            spine2_links.append((getattr(vars, dx_name), getattr(vars, dx_port)))
    for dut, ifname in spine2_links:
        st.log(f"Shutting down {ifname} on {dut}")
        st.config(dut, f"config interface shutdown {ifname}")
    
    # Shutdown second Spine1-Leaf links (D1D3P2 and D1D4P2) to force single path
    spine1_p2_links = [
        (vars.D1, vars.D1D3P2),  # Spine1 to Leaf0 (second link)
        (vars.D1, vars.D1D4P2),  # Spine1 to Leaf1 (second link)
        (vars.D3, vars.D3D1P2),  # Leaf0 to Spine1 (second link)
        (vars.D4, vars.D4D1P2),  # Leaf1 to Spine1 (second link)
    ]
    for dut, ifname in spine1_p2_links:
        st.log(f"Shutting down {ifname} on {dut}")
        st.config(dut, f"config interface shutdown {ifname}")
    
    st.wait(5)
    
    # Save links to test_info for restoration
    test_info['spine2_shutdown_links'] = spine2_links
    test_info['spine1_p2_shutdown_links'] = spine1_p2_links
    
    st.wait(10)  # Wait for speed changes to take effect
    st.log("Spine2 shutdown and Spine1 configuration complete")


def restore_spine_links():
    """
    Restore Spine2 links and Spine1 speed to original.
    Uses saved links from test_info.
    """
    global test_info
    st.banner("Restoring spine links")
    
    # Startup second Spine1-Leaf links (D1D3P2 and D1D4P2)
    for dut, ifname in test_info.get('spine1_p2_shutdown_links', []):
        st.log(f"Starting up {ifname} on {dut}")
        st.config(dut, f"config interface startup {ifname}")
    
    # Startup Spine2 links (both ends, all ports)
    for dut, ifname in test_info.get('spine2_shutdown_links', []):
        st.log(f"Starting up {ifname} on {dut}")
        st.config(dut, f"config interface startup {ifname}")
    
    st.wait(10)
    st.log("Spine links restored")

def compute_rate(if_str):
    return common_util.get_if_speed(vars.D3, if_str) * STREAM_FACTOR

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    global tb_dict
    global vars
    global test_info

    st.log("Setup topology started - 2:1 congestion TC3 test (2 src -> 1 dst)")
    vars = st.get_testbed_vars()

    # Reload QoS config and set TC-to-PG map on all DUTs
    for dut in st.get_dut_names():
        stream_api.init_qos_on_dut(dut)
    st.wait(5)

    test_info = {}
    test_info['tc'] = TRAFFIC_CLASS
    test_info['frame_size'] = FRAME_SIZE
    test_info['gbps'] = compute_rate(vars.D3T1P1)
    test_info['traffic_duration'] = TRAFFIC_DURATION

    # 2 spine + 2 leaf topology with 4 TGEN ports per leaf
    tb_dict = st.ensure_min_topology("D1D3:2", "D1D4:2", "D2D3:1", "D2D4:1",
                                     "D3T1:2", "D4T1:1")


    # Clean up any existing IP configurations
    for dut in st.get_dut_names():
        qos_test_utils.cleanup_config(dut)

    # Configure 2-spine 2-leaf topology with IP addresses and routes
    stream_api.config_two_spine_two_leaf_topo(tb_dict)

    # Shutdown Spine2 links
    configure_spine1_only_100g()

    st.log("Setup topology done")

    yield

    # Restore spine links before cleanup
    restore_spine_links()
    

def create_all_streams():
    """
    Create 2 traffic streams from Leaf0 (D3) converging to single port on Leaf1 (D4).
    This creates a 2:1 oversubscription scenario (120 Gbps into 1 egress port).
    """
    streams = []
    pps = stream_api.gbps_to_pps(test_info['gbps'], FRAME_SIZE)

    for src_port, dst_port in STREAM_DEFS:
        st.log(f"Creating stream: {src_port} -> {dst_port}, TC={TRAFFIC_CLASS}, Rate={test_info['gbps']}Gbps")
        stream = stream_api.create_traffic_stream(
            tb_dict, src_port, dst_port, FRAME_SIZE, pps, TRAFFIC_CLASS
        )
        if stream is None:
            st.error(f"Failed to create stream {src_port} -> {dst_port}")
            return None
        stream['src_port'] = src_port
        stream['dst_port'] = dst_port
        stream['tc'] = TRAFFIC_CLASS
        stream['pps'] = pps
        streams.append(stream)
        st.log(f"Stream created: {stream['stream_id']}")

    return streams


def run_traffic_and_collect_stats(streams, duration):
    """
    Start all streams, wait for duration, stop and collect stats.
    """
    st.banner(f"Starting {len(streams)} streams for {duration} seconds")

    # Start all streams
    stream_api.start_traffic_stream()
    st.wait(duration)

    # Stop all streams
    stream_api.stop_traffic_stream()
    st.wait(5)

    # Collect statistics
    stats = stream_api.collect_traffic_stream_stats()
    return stats


def analyze_results(streams, stats):
    """
    Analyze traffic statistics and report pass/fail for each stream.

    For 2:1 congestion with TC3 (lossless queue):
    - PFC should be triggered to pause senders
    - Expect very low loss (<1%) due to PFC backpressure

    Returns:
        (passed, loss_info): passed is bool, loss_info is summary string
    """
    if 'traffic_item' not in stats:
        st.error("Failed to find traffic_item in stats")
        return False, "no traffic stats"

    item_stats = stats['traffic_item']
    all_passed = True
    total_tx = 0
    total_rx = 0
    loss_parts = []

    st.banner("Traffic Results Summary (2:1 Congestion Test)")

    for stream in streams:
        stream_id = stream['stream_id']
        if stream_id not in item_stats:
            st.error(f"No stats found for stream {stream_id}")
            all_passed = False
            loss_parts.append(f"{stream['src_port']}->no_stats")
            continue

        stream_stats = item_stats[stream_id]
        tx_pkts = int(stream_stats.get('tx', {}).get('total_pkts', 0))
        rx_pkts = int(stream_stats.get('rx', {}).get('total_pkts', 0))
        loss_percent = float(stream_stats.get('rx', {}).get('loss_percent', 0))

        total_tx += tx_pkts
        total_rx += rx_pkts
        loss_parts.append(f"{stream['src_port']}: {loss_percent:.2f}%")

        st.log(f"Stream {stream['src_port']} -> {stream['dst_port']}: "
               f"TX={tx_pkts}, RX={rx_pkts}, Loss%={loss_percent:.2f}")

        # For TC3 lossless traffic with PFC, we expect very low loss even with congestion
        if loss_percent > 1.0:
            st.log(f"FAIL: Stream {stream['src_port']} -> {stream['dst_port']} "
                   f"has {loss_percent:.2f}% loss (expected < 1% with PFC)")
            all_passed = False
        else:
            st.log(f"PASS: Stream {stream['src_port']} -> {stream['dst_port']} "
                   f"has {loss_percent:.2f}% loss")

    # Summary
    overall_loss = ((total_tx - total_rx) / total_tx * 100) if total_tx > 0 else 0
    loss_info = f"Loss[{', '.join(loss_parts)}] Overall={overall_loss:.2f}%"
    st.log(f"Overall: TX={total_tx}, RX={total_rx}, Loss%={overall_loss:.2f}")

    return all_passed, loss_info


def cleanup_streams(streams):
    """
    Delete all traffic streams.
    """
    for stream in streams:
        stream_api.delete_traffic_stream(stream)


def collect_counters(label):
    """
    Collect PFC counters, queue counters, and interface counters on all DUTs.
    
    Args:
        label: String label for log output (e.g., "BEFORE TRAFFIC", "AFTER TRAFFIC")
    """
    global vars
    
    st.banner(f"Collecting counters: {label}")
    
    # Define relevant interfaces for each DUT
    # D1 (Spine1): links to D3 and D4
    # D2 (Spine2): links to D3 and D4 (shutdown but collect anyway)
    # D3 (Leaf0): IXIA ports and spine links
    # D4 (Leaf1): IXIA ports and spine links
    dut_interfaces = {
        vars.D1: [vars.D1D3P1, vars.D1D4P1],
        vars.D2: [vars.D2D3P1, vars.D2D4P1],
        vars.D3: [vars.D3T1P1, vars.D3T1P2, vars.D3D1P1, vars.D3D2P1],
        vars.D4: [vars.D4T1P1, vars.D4D1P1, vars.D4D2P1],
    }
    
    # Add optional interfaces if they exist
    if hasattr(vars, 'D1D3P2'):
        dut_interfaces[vars.D1].append(vars.D1D3P2)
    if hasattr(vars, 'D1D4P2'):
        dut_interfaces[vars.D1].append(vars.D1D4P2)
    if hasattr(vars, 'D3D1P2'):
        dut_interfaces[vars.D3].append(vars.D3D1P2)
    if hasattr(vars, 'D4D1P2'):
        dut_interfaces[vars.D4].append(vars.D4D1P2)
    
    for dut, interfaces in dut_interfaces.items():
        st.log(f"=== {dut} counters ({label}) ===")
        
        # PFC counters
        st.log(f"[{dut}] PFC counters:")
        st.show(dut, "show pfc counters", skip_tmpl=True)
        
        # Queue counters
        st.log(f"[{dut}] Queue counters:")
        st.show(dut, "show queue counters", skip_tmpl=True)
        
        # Interface counters for relevant interfaces
        intf_pattern = "|".join(interfaces)
        st.log(f"[{dut}] Interface counters for: {intf_pattern}")
        st.show(dut, f"show interface counters | egrep '{intf_pattern}'", skip_tmpl=True)


def test_2to1_congestion_tc3():
    """
    Test 2:1 congestion scenario with TC3 (lossless queue).

    Scaled Jira Scenario:
        Original:  360G×2 streams through 400G×2 spines (1.8:1 oversubscription)
        Scaled:    99G×2  streams through 100G×1 spine  (0.9:1 - bottleneck at spine)

    Traffic Paths:
        T1D3P1 (99 Gbps) -> D3 -> Spine1(100G) -> D4 -> T1D4P1
        T1D3P2 (99 Gbps) -> D3 -> Spine1(100G) -> D4 -> T1D4P1
                                                     ^
                                                     |-- 198 Gbps through 100G spine

    Spine2 is shutdown. Spine1 is set to 100G.
    Both streams use TC3 (lossless queue) at 99 Gbps each = 198 Gbps total.
    With PFC enabled, the spine should send pause frames back to the source leaf,
    preventing packet loss despite the congestion at the spine link.
    """
    st.banner("Test STARTED: 2:1 Congestion TC3 (PFC Lossless)")

    # Log the test configuration
    st.log(f"Stream rate: {test_info['gbps']} Gbps × 2 = {test_info['gbps'] * 2} Gbps total")
    st.log("Topology: Spine2 shutdown, Spine1 at 100G")
    st.log(f"Congestion point: {test_info['gbps'] * 2} Gbps through 100G spine link")
    
    # Create 2 streams converging to single destination
    streams = create_all_streams()
    if streams is None or len(streams) != 2:
        st.report_fail('msg', 'Failed to create all 2 traffic streams')
        return

    # Ingress ports on D3 facing IXIA sources (where PFC TX happens)
    pfc_intfs = [vars.D3T1P1, vars.D3T1P2]

    try:
        # Collect counters before traffic
        collect_counters("BEFORE TRAFFIC")

        # Snapshot PFC TX before traffic
        pre_pfc = {intf: common_util.get_pfc_tx_count(vars.D3, intf, TRAFFIC_CLASS)
                   for intf in pfc_intfs}

        # Run traffic and collect stats
        stats = run_traffic_and_collect_stats(streams, TRAFFIC_DURATION)

        # Snapshot PFC TX after traffic
        post_pfc = {intf: common_util.get_pfc_tx_count(vars.D3, intf, TRAFFIC_CLASS)
                    for intf in pfc_intfs}
        pfc_deltas = {intf: post_pfc[intf] - pre_pfc[intf] for intf in pfc_intfs}

        # Collect counters after traffic
        collect_counters("AFTER TRAFFIC")

        # Analyze results
        passed, loss_info = analyze_results(streams, stats)

        # Build result message with PFC deltas
        pfc_str = ' '.join(f'{intf}={pfc_deltas[intf]}' for intf in pfc_intfs)
        if passed:
            st.report_pass('msg',
                f'2:1 congestion test passed - {loss_info} PFC Tx: {pfc_str}')
        else:
            st.report_fail('msg',
                f'2:1 congestion test FAILED - {loss_info} PFC Tx: {pfc_str}')

    except Exception as e:
        st.error(f"Test failed with exception: {e}")
        st.report_fail('msg', f'Test exception: {e}')

    finally:
        # Cleanup streams
        cleanup_streams(streams)
