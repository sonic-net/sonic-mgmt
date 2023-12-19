import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts # noqa F401
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector,\
    get_egress_lossless_buffer_size, stop_pfcwd, disable_packet_aging,\
    sec_to_nanosec, get_pfc_frame_count, packet_capture, config_capture_pkt # noqa F401
from tests.common.snappi_tests.port import select_ports, select_tx_port # noqa F401
from tests.common.snappi_tests.snappi_helpers import wait_for_arp # noqa F401
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config, generate_test_flows,\
    generate_background_flows, generate_pause_flows, run_traffic, verify_pause_flow, verify_basic_test_flow,\
    verify_background_flow, verify_pause_frame_count_dut, verify_egress_queue_frame_count, verify_in_flight_buffer_pkts,\
    verify_unset_cev_pause_frame_count # noqa F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams # noqa F401

logger = logging.getLogger(__name__)

PAUSE_FLOW_NAME = 'Pause Storm'
TEST_FLOW_NAME = 'Test Flow'
TEST_FLOW_AGGR_RATE_PERCENT = 45
BG_FLOW_NAME = 'Background Flow'
BG_FLOW_AGGR_RATE_PERCENT = 45
DATA_PKT_SIZE = 1024
data_flow_pkt_size = 1024
DATA_FLOW_DURATION_SEC = 2
DATA_FLOW_DELAY_SEC = 1
data_flow_delay_sec = 1
SNAPPI_POLL_DELAY_SEC = 2
TOLERANCE_THRESHOLD = 0.05


def run_pfc_test(api,
                 testbed_config,
                 port_config_list,
                 conn_data,
                 fanout_data,
                 global_pause,
                 pause_prio_list,
                 test_prio_list,
                 bg_prio_list,
                 prio_dscp_map,
                 test_traffic_pause,
                 snappi_extra_params=None):
    """
    Run a multidut PFC test
    Args:
        api (obj): snappi session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        global_pause (bool): if pause frame is IEEE 802.3X pause
        pause_prio_list (list): priorities to pause for pause frames
        test_prio_list (list): priorities of test flows
        bg_prio_list (list): priorities of background flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        test_traffic_pause (bool): if test flows are expected to be paused
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
        N/A
    """

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    duthost1 = snappi_extra_params.multi_dut_params.duthost1
    rx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[0]
    rx_port_id = rx_port["port_id"]
    duthost2 = snappi_extra_params.multi_dut_params.duthost2
    tx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[1]

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    stop_pfcwd(duthost1, rx_port['asic_value'])
    disable_packet_aging(duthost1)
    stop_pfcwd(duthost2, tx_port['asic_value'])
    disable_packet_aging(duthost2)

    """ Rate percent must be an integer """
    test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT / len(test_prio_list))
    bg_flow_rate_percent = int(BG_FLOW_AGGR_RATE_PERCENT / len(bg_prio_list))

    if snappi_extra_params.headroom_test_params is not None:
        global DATA_FLOW_DURATION_SEC
        DATA_FLOW_DURATION_SEC = 10
        global data_flow_delay_sec
        data_flow_delay_sec = 2

        # Set up pfc delay parameter
        l1_config = testbed_config.layer1[0]
        pfc = l1_config.flow_control.ieee_802_1qbb
        pfc.pfc_delay = snappi_extra_params.headroom_test_params[0]

    if snappi_extra_params.packet_capture_type != packet_capture.NO_CAPTURE:
        # Setup capture config
        config_capture_pkt(testbed_config=testbed_config,
                           port_id=rx_port_id,
                           capture_type=snappi_extra_params.packet_capture_type,
                           capture_name=snappi_extra_params.packet_capture_type.value + "_" + str(rx_port_id))

    # Generate base traffic config
    snappi_extra_params.base_flow_config = setup_base_traffic_config(testbed_config=testbed_config,
                                                                     port_config_list=port_config_list,
                                                                     port_id=rx_port_id)
    ########
    # Generate test flow config
    generate_test_flows(testbed_config=testbed_config,
                        test_flow_name=TEST_FLOW_NAME,
                        test_flow_prio_list=test_prio_list,
                        test_flow_rate_percent=test_flow_rate_percent,
                        test_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                        test_flow_delay_sec=data_flow_delay_sec,
                        test_flow_pkt_size=data_flow_pkt_size,
                        prio_dscp_map=prio_dscp_map,
                        snappi_extra_params=snappi_extra_params)

    # Generate background flow config
    generate_background_flows(testbed_config=testbed_config,
                              bg_flow_name=BG_FLOW_NAME,
                              bg_flow_prio_list=bg_prio_list,
                              bg_flow_rate_percent=bg_flow_rate_percent,
                              bg_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                              bg_flow_delay_sec=data_flow_delay_sec,
                              bg_flow_pkt_size=data_flow_pkt_size,
                              prio_dscp_map=prio_dscp_map,
                              snappi_extra_params=snappi_extra_params)

    # Generate pause storm config
    generate_pause_flows(testbed_config=testbed_config,
                         pause_flow_name=PAUSE_FLOW_NAME,
                         pause_prio_list=pause_prio_list,
                         global_pause=global_pause,
                         snappi_extra_params=snappi_extra_params)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

    """ Run traffic """
    flow_stats = run_traffic(api=api,
                             config=testbed_config,
                             data_flow_names=data_flow_names,
                             all_flow_names=all_flow_names,
                             exp_dur_sec=DATA_FLOW_DURATION_SEC + data_flow_delay_sec,
                             snappi_extra_params=snappi_extra_params)

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])

    # Verify pause flows
    verify_pause_flow(flow_metrics=flow_stats,
                      pause_flow_name=PAUSE_FLOW_NAME)

    # Verify background flows
    verify_background_flow(flow_metrics=flow_stats,
                           bg_flow_name=BG_FLOW_NAME,
                           bg_flow_rate_percent=bg_flow_rate_percent,
                           bg_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                           bg_flow_pkt_size=data_flow_pkt_size,
                           speed_gbps=speed_gbps,
                           tolerance=TOLERANCE_THRESHOLD,
                           snappi_extra_params=snappi_extra_params)

    # Verify basic test flows metrics from ixia
    verify_basic_test_flow(flow_metrics=flow_stats,
                           test_flow_name=TEST_FLOW_NAME,
                           test_flow_rate_percent=test_flow_rate_percent,
                           test_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                           test_flow_pkt_size=data_flow_pkt_size,
                           speed_gbps=speed_gbps,
                           tolerance=TOLERANCE_THRESHOLD,
                           test_flow_pause=test_traffic_pause,
                           snappi_extra_params=snappi_extra_params)

    if test_traffic_pause:
        # Verify in flight TX packets count relative to switch buffer size
        verify_in_flight_buffer_pkts(duthost=duthost2,
                                     flow_metrics=flow_stats,
                                     test_flow_name=TEST_FLOW_NAME,
                                     test_flow_pkt_size=data_flow_pkt_size,
                                     snappi_extra_params=snappi_extra_params)
        # Verify PFC pause frame count
        verify_pause_frame_count_dut(duthost=duthost2,
                                     snappi_extra_params=snappi_extra_params)
