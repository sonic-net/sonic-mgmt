import logging
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts  # noqa F401
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector,\
    get_lossless_buffer_size, get_pg_dropped_packets,\
    disable_packet_aging, enable_packet_aging, sec_to_nanosec,\
    get_pfc_frame_count, packet_capture, config_capture_pkt,\
    traffic_flow_mode, calc_pfc_pause_flow_rate, get_tx_frame_count      # noqa F401
from tests.common.snappi_tests.port import select_ports, select_tx_port  # noqa F401
from tests.common.snappi_tests.snappi_helpers import wait_for_arp  # noqa F401
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config, generate_test_flows, \
    generate_background_flows, generate_pause_flows, run_traffic, verify_pause_flow, verify_basic_test_flow, \
    verify_background_flow, verify_pause_frame_count_dut, verify_egress_queue_frame_count, \
    verify_in_flight_buffer_pkts, verify_unset_cev_pause_frame_count, verify_tx_frame_count_dut, \
    verify_rx_frame_count_dut
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.read_pcap import validate_pfc_frame


logger = logging.getLogger(__name__)

dut_port_config = []
PAUSE_FLOW_NAME = 'Pause Storm'
TEST_FLOW_NAME = 'Test Flow'
TEST_FLOW_AGGR_RATE_PERCENT = 45
BG_FLOW_NAME = 'Background Flow'
BG_FLOW_AGGR_RATE_PERCENT = 45
data_flow_pkt_size = 1024
DATA_FLOW_DURATION_SEC = 15
data_flow_delay_sec = 1
SNAPPI_POLL_DELAY_SEC = 2
PAUSE_FLOW_DUR_BASE_SEC = data_flow_delay_sec + DATA_FLOW_DURATION_SEC
TOLERANCE_THRESHOLD = 0.05
CONTINUOUS_MODE = -5
ANSIBLE_POLL_DELAY_SEC = 4


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
                 test_flow_is_lossless=True,
                 snappi_extra_params=None,
                 flow_factor=1):
    """
    Run a multidut PFC test
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

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    # Traffic flow:
    # tx_port (TGEN) --- ingress DUT --- egress DUT --- rx_port (TGEN)

    # initialize the (duthost, port) set.
    dut_asics_to_be_configured = set()

    rx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[0]
    egress_duthost = rx_port['duthost']
    dut_asics_to_be_configured.add((egress_duthost, rx_port['asic_value']))

    tx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[1]
    ingress_duthost = tx_port['duthost']
    dut_asics_to_be_configured.add((ingress_duthost, tx_port['asic_value']))

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    global DATA_FLOW_DURATION_SEC
    global data_flow_delay_sec

    # Port id of Rx port for traffic config
    port_id = 0

    # Rate percent must be an integer
    bg_flow_rate_percent = int((BG_FLOW_AGGR_RATE_PERCENT / flow_factor) / len(bg_prio_list))
    test_flow_rate_percent = int((TEST_FLOW_AGGR_RATE_PERCENT / flow_factor) / len(test_prio_list))

    # Generate base traffic config
    snappi_extra_params.base_flow_config = setup_base_traffic_config(testbed_config=testbed_config,
                                                                     port_config_list=port_config_list,
                                                                     port_id=port_id)

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(float(speed_str.split('_')[1]))

    if snappi_extra_params.headroom_test_params is not None:
        DATA_FLOW_DURATION_SEC += 10
        data_flow_delay_sec += 2

        # Set up pfc delay parameter
        l1_config = testbed_config.layer1[0]
        pfc = l1_config.flow_control.ieee_802_1qbb
        pfc.pfc_delay = snappi_extra_params.headroom_test_params[0]

    if snappi_extra_params.poll_device_runtime:
        # If the switch needs to be polled as traffic is running for stats,
        # then the test runtime needs to be increased for the polling delay
        DATA_FLOW_DURATION_SEC += ANSIBLE_POLL_DELAY_SEC
        data_flow_delay_sec = ANSIBLE_POLL_DELAY_SEC

    if snappi_extra_params.packet_capture_type != packet_capture.NO_CAPTURE:
        # Setup capture config
        if snappi_extra_params.is_snappi_ingress_port_cap:
            # packet capture is required on the ingress snappi port
            snappi_extra_params.packet_capture_ports = [snappi_extra_params.base_flow_config["rx_port_name"]]
        else:
            # packet capture will be on the egress snappi port
            snappi_extra_params.packet_capture_ports = [snappi_extra_params.base_flow_config["tx_port_name"]]

        snappi_extra_params.packet_capture_file = snappi_extra_params.packet_capture_type.value

        config_capture_pkt(testbed_config=testbed_config,
                           port_names=snappi_extra_params.packet_capture_ports,
                           capture_type=snappi_extra_params.packet_capture_type,
                           capture_name=snappi_extra_params.packet_capture_file)
        logger.info("Packet capture file: {}.pcapng".format(snappi_extra_params.packet_capture_file))

    # Set default traffic flow configs if not set
    if snappi_extra_params.traffic_flow_config.data_flow_config is None:
        snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_name": TEST_FLOW_NAME,
            "flow_dur_sec": DATA_FLOW_DURATION_SEC,
            "flow_rate_percent": test_flow_rate_percent,
            "flow_rate_pps": None,
            "flow_rate_bps": None,
            "flow_pkt_size": data_flow_pkt_size,
            "flow_pkt_count": None,
            "flow_delay_sec": data_flow_delay_sec,
            "flow_traffic_type": traffic_flow_mode.FIXED_DURATION
        }

    if snappi_extra_params.traffic_flow_config.background_flow_config is None and \
       snappi_extra_params.gen_background_traffic:
        snappi_extra_params.traffic_flow_config.background_flow_config = {
            "flow_name": BG_FLOW_NAME,
            "flow_dur_sec": DATA_FLOW_DURATION_SEC,
            "flow_rate_percent": bg_flow_rate_percent,
            "flow_rate_pps": None,
            "flow_rate_bps": None,
            "flow_pkt_size": data_flow_pkt_size,
            "flow_pkt_count": None,
            "flow_delay_sec": data_flow_delay_sec,
            "flow_traffic_type": traffic_flow_mode.FIXED_DURATION
        }

    if snappi_extra_params.traffic_flow_config.pause_flow_config is None:
        snappi_extra_params.traffic_flow_config.pause_flow_config = {
            "flow_name": PAUSE_FLOW_NAME,
            "flow_dur_sec": None,
            "flow_rate_percent": None,
            "flow_rate_pps": calc_pfc_pause_flow_rate(speed_gbps),
            "flow_rate_bps": None,
            "flow_pkt_size": 64,
            "flow_pkt_count": None,
            "flow_delay_sec": 0,
            "flow_traffic_type": traffic_flow_mode.CONTINUOUS
        }

    if snappi_extra_params.packet_capture_type == packet_capture.PFC_CAPTURE:
        # PFC pause frame capture is requested
        valid_pfc_frame_test = True
    else:
        # PFC pause frame capture is not requested
        valid_pfc_frame_test = False

    if valid_pfc_frame_test:
        snappi_extra_params.traffic_flow_config.pause_flow_config["flow_dur_sec"] = DATA_FLOW_DURATION_SEC + \
            data_flow_delay_sec + SNAPPI_POLL_DELAY_SEC + PAUSE_FLOW_DUR_BASE_SEC
        snappi_extra_params.traffic_flow_config.pause_flow_config["flow_traffic_type"] = \
            traffic_flow_mode.FIXED_DURATION

    no_of_streams = 1
    if egress_duthost.facts['asic_type'] == "cisco-8000":
        if not test_flow_is_lossless:
            no_of_streams = 6

    # Generate test flow config
    generate_test_flows(testbed_config=testbed_config,
                        test_flow_prio_list=test_prio_list,
                        prio_dscp_map=prio_dscp_map,
                        number_of_streams=no_of_streams,
                        snappi_extra_params=snappi_extra_params)

    if snappi_extra_params.gen_background_traffic:
        # Generate background flow config
        generate_background_flows(testbed_config=testbed_config,
                                  bg_flow_prio_list=bg_prio_list,
                                  prio_dscp_map=prio_dscp_map,
                                  snappi_extra_params=snappi_extra_params)

    # Generate pause storm config
    generate_pause_flows(testbed_config=testbed_config,
                         pause_prio_list=pause_prio_list,
                         global_pause=global_pause,
                         snappi_extra_params=snappi_extra_params)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

    # Clear PFC, queue and interface counters before traffic run
    duthost = egress_duthost
    duthost.command("pfcstat -c")
    time.sleep(1)
    duthost.command("sonic-clear queuecounters")
    time.sleep(1)
    duthost.command("sonic-clear counters")
    time.sleep(1)

    """ Run traffic """
    tgen_flow_stats, switch_flow_stats, in_flight_flow_metrics = run_traffic(duthost=duthost,
                                                                             api=api,
                                                                             config=testbed_config,
                                                                             data_flow_names=data_flow_names,
                                                                             all_flow_names=all_flow_names,
                                                                             exp_dur_sec=DATA_FLOW_DURATION_SEC +
                                                                             data_flow_delay_sec,
                                                                             snappi_extra_params=snappi_extra_params)

    # Reset pfc delay parameter
    pfc = testbed_config.layer1[0].flow_control.ieee_802_1qbb
    pfc.pfc_delay = 0

    # Verify PFC pause frames
    if valid_pfc_frame_test:
        is_valid_pfc_frame, error_msg = validate_pfc_frame(snappi_extra_params.packet_capture_file + ".pcapng")
        pytest_assert(is_valid_pfc_frame, error_msg)
        return

    # Verify pause flows
    verify_pause_flow(flow_metrics=tgen_flow_stats,
                      pause_flow_name=PAUSE_FLOW_NAME)

    if snappi_extra_params.gen_background_traffic:
        # Verify background flows
        verify_background_flow(flow_metrics=tgen_flow_stats,
                               speed_gbps=speed_gbps,
                               tolerance=TOLERANCE_THRESHOLD,
                               snappi_extra_params=snappi_extra_params)

    # Verify basic test flows metrics from ixia
    verify_basic_test_flow(flow_metrics=tgen_flow_stats,
                           speed_gbps=speed_gbps,
                           tolerance=TOLERANCE_THRESHOLD,
                           test_flow_pause=test_traffic_pause,
                           snappi_extra_params=snappi_extra_params)

    # Verify PFC pause frame count on the DUT
    verify_pause_frame_count_dut(rx_dut=ingress_duthost,
                                 tx_dut=egress_duthost,
                                 test_traffic_pause=test_traffic_pause,
                                 global_pause=global_pause,
                                 snappi_extra_params=snappi_extra_params)

    # Verify in flight TX lossless packets do not leave the DUT when traffic is expected
    # to be paused, or leave the DUT when the traffic is not expected to be paused
    # Verifying the packets on DUT egress, especially for multi line card scenario
    verify_egress_queue_frame_count(duthost=egress_duthost,
                                    switch_flow_stats=switch_flow_stats,
                                    test_traffic_pause=test_traffic_pause,
                                    snappi_extra_params=snappi_extra_params)

    if test_traffic_pause:
        # Verify in flight TX packets count relative to switch buffer size
        verify_in_flight_buffer_pkts(duthost=egress_duthost,
                                     flow_metrics=in_flight_flow_metrics,
                                     snappi_extra_params=snappi_extra_params,
                                     asic_value=tx_port['asic_value'])
    else:
        # Verify zero pause frames are counted when the PFC class enable vector is not set
        verify_unset_cev_pause_frame_count(duthost=duthost,
                                           snappi_extra_params=snappi_extra_params)

    if test_traffic_pause and not snappi_extra_params.gen_background_traffic:
        # Verify TX frame count on the DUT when traffic is expected to be paused
        # and only test traffic flows are generated
        verify_tx_frame_count_dut(duthost=duthost,
                                  snappi_extra_params=snappi_extra_params)

        # Verify TX frame count on the DUT when traffic is expected to be paused
        # and only test traffic flows are generated
        verify_rx_frame_count_dut(duthost=duthost,
                                  snappi_extra_params=snappi_extra_params)


def run_tx_drop_counter(
                        api,
                        testbed_config,
                        port_config_list,
                        dut_port,
                        test_prio_list,
                        prio_dscp_map,
                        snappi_extra_params=None):

    pytest_assert(testbed_config is not None, 'Failed to get L2/3 testbed config')

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    rx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[0]
    duthost = rx_port['duthost']
    port_id = 0

    # Generate base traffic config
    snappi_extra_params.base_flow_config = setup_base_traffic_config(testbed_config=testbed_config,
                                                                     port_config_list=port_config_list,
                                                                     port_id=port_id)

    test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT / len(test_prio_list))

    # Set default traffic flow configs if not set
    if snappi_extra_params.traffic_flow_config.data_flow_config is None:
        snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_name": TEST_FLOW_NAME,
            "flow_dur_sec": DATA_FLOW_DURATION_SEC,
            "flow_rate_percent": test_flow_rate_percent,
            "flow_rate_pps": None,
            "flow_rate_bps": None,
            "flow_pkt_size": data_flow_pkt_size,
            "flow_pkt_count": None,
            "flow_delay_sec": data_flow_delay_sec,
            "flow_traffic_type": traffic_flow_mode.FIXED_DURATION
        }

    # Generate test flow config
    generate_test_flows(testbed_config=testbed_config,
                        test_flow_prio_list=test_prio_list,
                        prio_dscp_map=prio_dscp_map,
                        snappi_extra_params=snappi_extra_params)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

    duthost.command("sonic-clear counters")
    duthost.command("sonic-clear queuecounters")
    # Collect metrics from DUT before traffic
    tx_ok_frame_count, tx_dut_drop_frames = get_tx_frame_count(duthost, dut_port)

    """ Run traffic """
    tgen_flow_stats, _, _ = run_traffic(
                                        duthost=duthost,
                                        api=api,
                                        config=testbed_config,
                                        data_flow_names=data_flow_names,
                                        all_flow_names=all_flow_names,
                                        exp_dur_sec=DATA_FLOW_DURATION_SEC +
                                        data_flow_delay_sec,
                                        snappi_extra_params=snappi_extra_params)
    link_state = None
    try:
        time.sleep(1)
        # Collect metrics from DUT once again
        tx_ok_frame_count_1, tx_dut_drop_frames_1 = get_tx_frame_count(duthost, dut_port)

        pytest_assert(tx_ok_frame_count_1 > tx_ok_frame_count and tx_dut_drop_frames_1 == tx_dut_drop_frames,
                      "DUT Port {} : TX ok counter before {} after {}, Tx drop counter before {} after {} not expected".
                      format(dut_port, tx_ok_frame_count, tx_ok_frame_count_1,
                             tx_dut_drop_frames, tx_dut_drop_frames_1))

        # Set port name of the Ixia port connected to dut_port
        port_names = snappi_extra_params.base_flow_config["rx_port_name"]
        # Create a link state object for ports
        link_state = api.link_state()
        # Apply the state to  port
        link_state.port_names = [port_names]
        # Set  port down (shut)
        link_state.state = link_state.DOWN
        api.set_link_state(link_state)
        logger.info("Snappi port {} is set to DOWN".format(port_names))
        time.sleep(1)
        # Collect metrics from DUT  again
        _, tx_dut_drop_frames = get_tx_frame_count(duthost, dut_port)

        logger.info("Sleeping for 90 seconds")
        time.sleep(90)
        # Collect metrics from DUT once again
        _, tx_dut_drop_frames_1 = get_tx_frame_count(duthost, dut_port)

        pytest_assert(tx_dut_drop_frames == tx_dut_drop_frames_1,
                      "Mismatch in TX drop counters post DUT port {} oper down".format(dut_port))
    finally:
        if link_state:
            # Bring the link back up
            link_state.state = link_state.UP
            api.set_link_state(link_state)
            logger.info("Snappi port {} is set to UP".format(port_names))
    return
