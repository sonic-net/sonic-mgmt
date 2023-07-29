import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts # noqa F401
from tests.common.snappi.snappi_helpers import get_dut_port_id
from tests.common.snappi.common_helpers import pfc_class_enable_vector,\
    get_lossless_buffer_size, get_pg_dropped_packets,\
    stop_pfcwd, disable_packet_aging, sec_to_nanosec,\
    get_pfc_frame_count, packet_capture, config_capture_pkt # noqa F401
from tests.common.snappi.port import select_ports, select_tx_port # noqa F401
from tests.common.snappi.snappi_helpers import wait_for_arp # noqa F401
from tests.common.snappi.traffic_generation import setup_base_traffic_config, generate_test_flows,\
    generate_background_flows, generate_pause_flows, run_traffic, verify_pause_flow, verify_basic_test_flow,\
    verify_background_flow, verify_pause_frame_count, verify_egress_queue_frame_count, verify_in_flight_buffer_pkts,\
    verify_unset_cev_pause_frame_count
from tests.common.snappi.snappi_test_params import SnappiTestParams
from tests.common.snappi.read_pcap import validate_pfc_frame


logger = logging.getLogger(__name__)

dut_port_config = []
PAUSE_FLOW_NAME = 'Pause Storm'
TEST_FLOW_NAME = 'Test Flow'
TEST_FLOW_AGGR_RATE_PERCENT = 45
BG_FLOW_NAME = 'Background Flow'
BG_FLOW_AGGR_RATE_PERCENT = 45
data_flow_pkt_size = 1024
DATA_FLOW_DURATION_SEC = 2
data_flow_delay_sec = 1
SNAPPI_POLL_DELAY_SEC = 2
TOLERANCE_THRESHOLD = 0.05


def run_pfc_test(api,
                 testbed_config,
                 port_config_list,
                 conn_data,
                 fanout_data,
                 duthost,
                 dut_port,
                 global_pause,
                 pause_prio_list,
                 test_prio_list,
                 bg_prio_list,
                 prio_dscp_map,
                 test_traffic_pause,
                 snappi_extra_params=None):
    """
    Run a PFC test
    Args:
        api (obj): snappi session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
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

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    stop_pfcwd(duthost)
    disable_packet_aging(duthost)

    # Get the ID of the port to test
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Fail to get ID for port {}'.format(dut_port))

    # Rate percent must be an integer
    bg_flow_rate_percent = int(BG_FLOW_AGGR_RATE_PERCENT / len(bg_prio_list))
    test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT / len(test_prio_list))

    if snappi_extra_params.headroom_test_params is not None:
        global DATA_FLOW_DURATION_SEC
        DATA_FLOW_DURATION_SEC = 10
        global data_flow_delay_sec
        data_flow_delay_sec = 2

        # Set up pfc delay parameter
        l1_config = testbed_config.layer1[0]
        pfc = l1_config.flow_control.ieee_802_1qbb
        pfc.pfc_delay = snappi_extra_params.headroom_test_params[0]

    # Generate base traffic config
    snappi_extra_params.base_flow_config = setup_base_traffic_config(testbed_config=testbed_config,
                                                                     port_config_list=port_config_list,
                                                                     port_id=port_id)

    if snappi_extra_params.packet_capture_type != packet_capture.NO_CAPTURE:
        # Setup capture config
        if snappi_extra_params.is_tgen_ingress_port_cap:
            # packet capture is required on the ingress tgen port
            snappi_extra_params.packet_capture_ports = [snappi_extra_params.base_flow_config["rx_port_name"]]
        else:
            # packet capture will be on the egress tgen port
            snappi_extra_params.packet_capture_ports = [snappi_extra_params.base_flow_config["tx_port_name"]]

        snappi_extra_params.packet_capture_file = snappi_extra_params.packet_capture_type.value

        config_capture_pkt(testbed_config=testbed_config,
                           port_names=snappi_extra_params.packet_capture_ports,
                           capture_type=snappi_extra_params.packet_capture_type,
                           capture_name=snappi_extra_params.packet_capture_file)

        if snappi_extra_params.packet_capture_type == packet_capture.PFC_CAPTURE:
            # PFC pause frame capture is requested
            valid_pfc_frame_test = True
        else:
            # PFC pause frame capture is not requested
            valid_pfc_frame_test = False

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

    # Clear PFC and queue counters before traffic run
    duthost.command("pfcstat -c")
    duthost.command("sonic-clear queuecounters")

    """ Run traffic """
    flow_stats = run_traffic(api=api,
                             config=testbed_config,
                             data_flow_names=data_flow_names,
                             all_flow_names=all_flow_names,
                             exp_dur_sec=DATA_FLOW_DURATION_SEC + data_flow_delay_sec,
                             snappi_extra_params=snappi_extra_params)

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])

    # Reset pfc delay parameter
    pfc = testbed_config.layer1[0].flow_control.ieee_802_1qbb
    pfc.pfc_delay = 0

    # Verify PFC pause frames
    if valid_pfc_frame_test:
        is_valid_pfc_frame = validate_pfc_frame(snappi_extra_params.packet_capture_file + ".pcapng")
        pytest_assert(is_valid_pfc_frame, "PFC frames invalid")
        return

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
        verify_in_flight_buffer_pkts(duthost=duthost,
                                     flow_metrics=flow_stats,
                                     test_flow_name=TEST_FLOW_NAME,
                                     test_flow_pkt_size=data_flow_pkt_size,
                                     snappi_extra_params=snappi_extra_params)
        # Verify PFC pause frame count
        verify_pause_frame_count(duthost=duthost,
                                 snappi_extra_params=snappi_extra_params)
    else:
        # Verify zero pause frames are counted when the PFC class enable vector is not set
        verify_unset_cev_pause_frame_count(duthost=duthost,
                                           snappi_extra_params=snappi_extra_params)
        # Verify egress queue frame counts
        verify_egress_queue_frame_count(duthost=duthost,
                                        snappi_extra_params=snappi_extra_params)
