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
STREAM_RATE_GBPS = 99
FRAME_SIZE = 1000
TRAFFIC_DURATION = 60  # seconds

# Stream definitions: (src_port, dst_port)
STREAM_DEFS = [
    ('T1D3P1', 'T1D4P1'),
    ('T1D3P2', 'T1D4P2'),
    ('T1D3P3', 'T1D4P3'),
    ('T1D3P4', 'T1D4P4'),
]


@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    global tb_dict
    global vars
    global test_info

    st.log("Setup topology started - 4 stream TC3 test (Leaf0 to Leaf1)")

    test_info = {}
    test_info['tc'] = TRAFFIC_CLASS
    test_info['frame_size'] = FRAME_SIZE
    test_info['stream_rate_gbps'] = STREAM_RATE_GBPS
    test_info['traffic_duration'] = TRAFFIC_DURATION

    # 2 spine + 2 leaf topology with 4 TGEN ports per leaf
    tb_dict = st.ensure_min_topology("D1D3:2", "D1D4:2", "D2D3:1", "D2D4:1",
                                     "D3T1:4", "D4T1:4")
    vars = st.get_testbed_vars()

    # Reload QoS config and set TC-to-PG map on all DUTs
    for dut in st.get_dut_names():
        stream_api.init_qos_on_dut(dut)
    st.wait(5)

    # Clean up any existing IP configurations
    for dut in st.get_dut_names():
        qos_test_utils.cleanup_config(dut)

    # Configure 2-spine 2-leaf topology with IP addresses and routes
    stream_api.config_two_spine_two_leaf_topo(tb_dict)

    st.log("Setup topology done")

    yield


def create_all_streams():
    """
    Create 4 traffic streams from Leaf0 (D3) to Leaf1 (D4), all TC3.
    """
    streams = []
    pps = stream_api.gbps_to_pps(STREAM_RATE_GBPS, FRAME_SIZE)

    for src_port, dst_port in STREAM_DEFS:
        st.log(f"Creating stream: {src_port} -> {dst_port}, TC={TRAFFIC_CLASS}, Rate={STREAM_RATE_GBPS}Gbps")
        stream = stream_api.create_traffic_stream(
            tb_dict, src_port, dst_port, FRAME_SIZE, pps, TRAFFIC_CLASS
        )
        if stream is None:
            st.error(f"Failed to create stream {src_port} -> {dst_port}")
            return None
        stream['src_port'] = src_port
        stream['dst_port'] = dst_port
        stream['tc'] = TRAFFIC_CLASS
        stream['gbps'] = STREAM_RATE_GBPS
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
    """
    if 'traffic_item' not in stats:
        st.error("Failed to find traffic_item in stats")
        return False

    item_stats = stats['traffic_item']
    all_passed = True

    st.banner("Traffic Results Summary")

    for stream in streams:
        stream_id = stream['stream_id']
        if stream_id not in item_stats:
            st.error(f"No stats found for stream {stream_id}")
            all_passed = False
            continue

        stream_stats = item_stats[stream_id]
        tx_pkts = int(stream_stats.get('tx', {}).get('total_pkts', 0))
        rx_pkts = int(stream_stats.get('rx', {}).get('total_pkts', 0))
        loss_percent = float(stream_stats.get('rx', {}).get('loss_percent', 0))

        st.log(f"Stream {stream['src_port']} -> {stream['dst_port']}: "
               f"TX={tx_pkts}, RX={rx_pkts}, Loss%={loss_percent:.2f}")

        # For TC3 lossless traffic, we expect very low loss
        if loss_percent > 1.0:
            st.log(f"FAIL: Stream {stream['src_port']} -> {stream['dst_port']} "
                   f"has {loss_percent:.2f}% loss (expected < 1%)")
            all_passed = False
        else:
            st.log(f"PASS: Stream {stream['src_port']} -> {stream['dst_port']} "
                   f"has {loss_percent:.2f}% loss")

    return all_passed


def cleanup_streams(streams):
    """
    Delete all traffic streams.
    """
    for stream in streams:
        stream_api.delete_traffic_stream(stream)


def test_4stream_tc3_leaf_to_leaf():
    """
    Test 4 parallel TC3 streams from Leaf0 (D3) to Leaf1 (D4).

    Traffic Paths:
        T1D3P1 -> D3 -> Spine -> D4 -> T1D4P1
        T1D3P2 -> D3 -> Spine -> D4 -> T1D4P2
        T1D3P3 -> D3 -> Spine -> D4 -> T1D4P3
        T1D3P4 -> D3 -> Spine -> D4 -> T1D4P4

    All streams use TC3 (lossless queue) at 99 Gbps each.
    """
    st.banner("Test STARTED: 4 Stream TC3 Leaf-to-Leaf")

    # Create all 4 streams
    streams = create_all_streams()
    if streams is None or len(streams) != 4:
        st.report_fail('msg', 'Failed to create all 4 traffic streams')
        return

    try:
        # Run traffic and collect stats
        stats = run_traffic_and_collect_stats(streams, TRAFFIC_DURATION)

        # Analyze results
        passed = analyze_results(streams, stats)

        if passed:
            st.report_pass('msg', 'All 4 TC3 streams passed with acceptable loss')
        else:
            st.report_fail('msg', 'One or more streams had excessive loss')

    except Exception as e:
        st.error(f"Test failed with exception: {e}")
        st.report_fail('msg', f'Test exception: {e}')

    finally:
        # Cleanup streams
        cleanup_streams(streams)
