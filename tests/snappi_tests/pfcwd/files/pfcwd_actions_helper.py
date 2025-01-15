import logging
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts  # noqa F401
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector,\
    get_lossless_buffer_size, get_pg_dropped_packets,\
    stop_pfcwd, disable_packet_aging, sec_to_nanosec,\
    get_pfc_frame_count, packet_capture, config_capture_pkt,\
    start_pfcwd, enable_packet_aging, start_pfcwd_fwd, \
    traffic_flow_mode, calc_pfc_pause_flow_rate      # noqa F401
from tests.common.snappi_tests.port import select_ports, select_tx_port  # noqa F401
from tests.common.snappi_tests.snappi_helpers import wait_for_arp  # noqa F401
from tests.common.snappi_tests.traffic_generation import verify_pause_flow, \
    verify_basic_test_flow, verify_background_flow, verify_pause_frame_count_dut, \
    run_traffic_and_collect_stats, multi_base_traffic_config, verify_egress_queue_frame_count, \
    generate_test_flows, generate_background_flows, generate_pause_flows
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams


logger = logging.getLogger(__name__)

dut_port_config = []
PAUSE_FLOW_NAME = 'Pause Storm'
TEST_FLOW_NAME = 'Test Flow'
BG_FLOW_NAME = 'Background Flow'
TOLERANCE_THRESHOLD = 0.1
CONTINUOUS_MODE = -5
ANSIBLE_POLL_DELAY_SEC = 4
global DATA_FLOW_DURATION_SEC
global data_flow_delay_sec


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
                 test_def,
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
        dut_port (str): DUT port to test
        global_pause (bool): if pause frame is IEEE 802.3X pause
        pause_prio_list (list): priorities to pause for pause frames
        test_prio_list (list): priorities of test flows
        bg_prio_list (list): priorities of background flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        test_traffic_pause (bool): if test flows are expected to be paused
        test_def['enable_pause'] (bool) : if test expects no pause flow traffic.
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic

    Returns:
        N/A
    """

    TEST_FLOW_AGGR_RATE_PERCENT = test_def['TEST_FLOW_AGGR_RATE_PERCENT']
    BG_FLOW_AGGR_RATE_PERCENT = test_def['BG_FLOW_AGGR_RATE_PERCENT']
    data_flow_pkt_size = test_def['data_flow_pkt_size']
    DATA_FLOW_DURATION_SEC = test_def['DATA_FLOW_DURATION_SEC']
    data_flow_delay_sec = test_def['data_flow_delay_sec']
    SNAPPI_POLL_DELAY_SEC = test_def['SNAPPI_POLL_DELAY_SEC']
    PAUSE_FLOW_DUR_BASE_SEC = data_flow_delay_sec + DATA_FLOW_DURATION_SEC
    if test_def['imix']:
        fname = test_def['test_type'] + '_' + test_def['line_card_choice'] + '_' + 'IMIX'
    else:
        fname = test_def['test_type'] + '_' + test_def['line_card_choice'] + '_' + str(data_flow_pkt_size) + 'B'

    port_map = test_def['port_map']

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    # Traffic flow:
    # tx_port (TGEN) --- ingress DUT --- egress DUT --- rx_port (TGEN)

    rx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[0]
    egress_duthost = rx_port['duthost']

    tx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[-1]
    ingress_duthost = tx_port['duthost']
    dut_list = [egress_duthost, ingress_duthost]

    if (test_traffic_pause):
        logger.info("PFC receiving DUT is {}".format(egress_duthost.hostname))

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    if (test_def['enable_pfcwd_drop']):
        start_pfcwd(egress_duthost)
        start_pfcwd(ingress_duthost)
    elif (test_def['enable_pfcwd_fwd']):
        start_pfcwd_fwd(egress_duthost)
        start_pfcwd_fwd(ingress_duthost)
    else:
        stop_pfcwd(egress_duthost)
        stop_pfcwd(ingress_duthost)

    if (test_def['enable_credit_wd']):
        enable_packet_aging(egress_duthost, rx_port['asic_value'])
        enable_packet_aging(ingress_duthost, tx_port['asic_value'])
    else:
        disable_packet_aging(egress_duthost, rx_port['asic_value'])
        disable_packet_aging(ingress_duthost, tx_port['asic_value'])

    rx_port_id = 0

    # Rate percent must be an integer
    bg_flow_rate_percent = int(BG_FLOW_AGGR_RATE_PERCENT / len(bg_prio_list))
    test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT / len(test_prio_list))
    # Generate base traffic config
    if (port_map[0] == 2):
        for i in range(port_map[0]):
            rx_port_id = i
            tx_port_id = 2
            snappi_extra_params.base_flow_config_list.append(
                multi_base_traffic_config(testbed_config=testbed_config,
                                          port_config_list=port_config_list,
                                          rx_port_id=rx_port_id,
                                          tx_port_id=tx_port_id
                                          )
                )
    else:
        rx_port_id = 0
        for i in range(port_map[2]):
            tx_port_id = i+1
            snappi_extra_params.base_flow_config_list.append(
                multi_base_traffic_config(testbed_config=testbed_config,
                                          port_config_list=port_config_list,
                                          rx_port_id=rx_port_id,
                                          tx_port_id=tx_port_id
                                          )
                )

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])

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
            snappi_extra_params.packet_capture_ports = [snappi_extra_params.base_flow_config_list["rx_port_name"]]
        else:
            # packet capture will be on the egress snappi port
            snappi_extra_params.packet_capture_ports = [snappi_extra_params.base_flow_config_list["tx_port_name"]]

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
            "flow_pkt_count": None,
            "flow_pkt_size": data_flow_pkt_size,
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

    # PPS is high to ensure Storm is detected.
    # traffic_flow_mode is changed to BURST
    # Need to check how it works
    if (test_traffic_pause):
        if snappi_extra_params.traffic_flow_config.pause_flow_config is None:
            snappi_extra_params.traffic_flow_config.pause_flow_config = {
                "flow_name": PAUSE_FLOW_NAME,
                "flow_dur_sec": DATA_FLOW_DURATION_SEC+60,
                "flow_rate_percent": None,
                "flow_rate_pps": calc_pfc_pause_flow_rate(speed_gbps),
                "flow_rate_bps": None,
                "flow_pkt_size": 64,
                "flow_pkt_count": None,
                "flow_delay_sec": 0,
                "flow_traffic_type": traffic_flow_mode.FIXED_DURATION
            }

    if snappi_extra_params.packet_capture_type == packet_capture.PFC_CAPTURE:
        # PFC pause frame capture is requested
        valid_pfc_frame_test = True
    else:
        # PFC pause frame capture is not requested
        valid_pfc_frame_test = False

    if (test_traffic_pause):
        if valid_pfc_frame_test:
            snappi_extra_params.traffic_flow_config.pause_flow_config["flow_dur_sec"] = DATA_FLOW_DURATION_SEC + \
                data_flow_delay_sec + SNAPPI_POLL_DELAY_SEC + PAUSE_FLOW_DUR_BASE_SEC
            snappi_extra_params.traffic_flow_config.pause_flow_config["flow_traffic_type"] = \
                traffic_flow_mode.FIXED_DURATION

    # Generate test flow config
    for m in range(port_map[2]):
        generate_test_flows(testbed_config=testbed_config,
                            test_flow_prio_list=test_prio_list,
                            prio_dscp_map=prio_dscp_map,
                            snappi_extra_params=snappi_extra_params,
                            flow_index=m)

    if (test_def['background_traffic']):
        for m in range(port_map[2]):
            if snappi_extra_params.gen_background_traffic:
                # Generate background flow config
                generate_background_flows(testbed_config=testbed_config,
                                          bg_flow_prio_list=bg_prio_list,
                                          prio_dscp_map=prio_dscp_map,
                                          snappi_extra_params=snappi_extra_params,
                                          flow_index=m)

    # Generate pause storm config
    if (test_traffic_pause):
        for m in range(port_map[0]):
            generate_pause_flows(testbed_config=testbed_config,
                                 pause_prio_list=pause_prio_list,
                                 global_pause=global_pause,
                                 snappi_extra_params=snappi_extra_params,
                                 flow_index=m)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

    # Clear PFC, queue and interface counters before traffic run
    for dut in dut_list:
        dut.command("pfcstat -c \n")
        time.sleep(1)
        dut.command("sonic-clear queuecounters \n")
        time.sleep(1)
        dut.command("sonic-clear counters \n")
        time.sleep(1)

    exp_dur_sec = DATA_FLOW_DURATION_SEC + data_flow_delay_sec

    """ Run traffic """
    tgen_flow_stats, switch_flow_stats, test_stats = \
        run_traffic_and_collect_stats(rx_duthost=ingress_duthost,
                                      tx_duthost=egress_duthost,
                                      api=api,
                                      config=testbed_config,
                                      data_flow_names=data_flow_names,
                                      all_flow_names=all_flow_names,
                                      exp_dur_sec=exp_dur_sec,
                                      port_map=test_def['port_map'],
                                      fname=fname,
                                      stats_interval=test_def['stats_interval'],
                                      imix=test_def['imix'],
                                      snappi_extra_params=snappi_extra_params)

    test_check = test_def['test_check']
    if (not test_check['loss_expected']):
        # Check for loss packets on IXIA and DUT.
        if (test_def['enable_pfcwd_drop'] or test_def['enable_credit_wd']):
            pytest_assert(test_stats['tgen_loss_pkts'] == 0, 'Loss seen on TGEN')
        pytest_assert(test_stats['dut_loss_pkts'] == 0, 'Loss seen on DUT')

        # Check for Tx and Rx packets on IXIA for lossless and lossy streams.
        if (test_def['enable_pfcwd_drop'] or test_def['enable_credit_wd']):
            pytest_assert(test_stats['tgen_lossless_rx_pkts'] == test_stats['tgen_lossless_tx_pkts'],
                          'Losses observed in lossless traffic streams')
        pytest_assert(test_stats['tgen_lossy_rx_pkts'] == test_stats['tgen_lossy_tx_pkts'],
                      'Losses observed in lossy traffic streams')

        # Check for Rx packets between IXIA and DUT for lossy and lossless streams.
        if (test_def['enable_pfcwd_drop'] or test_def['enable_credit_wd']):
            pytest_assert(test_stats['tgen_lossless_rx_pkts'] == test_stats['dut_lossless_pkts'],
                          'Losses observed in lossless traffic streams on DUT Tx and IXIA Rx')
        pytest_assert(test_stats['tgen_lossy_rx_pkts'] == test_stats['dut_lossy_pkts'],
                      'Losses observed in lossy traffic streams on DUT Tx and IXIA Rx')
    else:
        # Check for lossless and lossy stream percentage drop for a given tolerance limit.
        lossless_drop = round((1 - float(test_stats['tgen_lossless_rx_pkts']) / test_stats['tgen_lossless_tx_pkts']), 2)
        lossy_drop = round((1 - float(test_stats['tgen_lossy_rx_pkts']) / test_stats['tgen_lossy_tx_pkts']), 2)
        logger.info('Lossless Drop %:{}, Lossy Drop %:{}'.format(lossless_drop, lossy_drop))
        pytest_assert((lossless_drop*100) <= test_check['lossless'], 'Lossless packet drop outside tolerance limit')
        pytest_assert((lossy_drop*100) <= test_check['lossy'], 'Lossy packet drop outside tolerance limit')

    # Checking if the actual line rate on egress is within tolerable limit of egress line speed.
    pytest_assert(((1 - test_stats['tgen_rx_rate'] / float(port_map[0]*port_map[1]))*100) <= test_check['speed_tol'],
                  'Egress speed beyond tolerance range')

    # Checking for PFC counts on DUT
    if (not test_check['pfc']):
        pytest_assert(test_stats['lossless_tx_pfc'] == 0, 'Error:PFC transmitted by DUT for lossless priorities')
        pytest_assert(test_stats['lossy_rx_tx_pfc'] == 0, 'Error:PFC transmitted by DUT for lossy priorities')
    else:
        if (test_stats['lossless_rx_pfc'] != 0 and (test_def['enable_pfcwd_drop'] or test_def['enable_pfcwd_fwd'])):
            pytest_assert(test_stats['lossless_tx_pfc'] == 0, 'Error:No Tx PFCs from DUT after receiving PFCs')
        if (test_stats['lossless_rx_pfc'] != 0 and
                (not test_def['enable_pfcwd_drop'] and not test_def['enable_pfcwd_fwd'])):
            pytest_assert(test_stats['lossless_tx_pfc'] != 0, 'Error:Tx PFCs should sent from DUT after receiving PFCs')
        pytest_assert(test_stats['lossy_rx_tx_pfc'] == 0, 'Error:Incorrect Rx/Tx PFCs on DUT for lossy priorities')

    # Reset pfc delay parameter
    pfc = testbed_config.layer1[0].flow_control.ieee_802_1qbb
    pfc.pfc_delay = 0

    for metric in tgen_flow_stats:
        if "Pause" in metric.name:
            PAUSE_FLW_NAME = metric.name

    # Verify pause flows
    if (test_traffic_pause):
        verify_pause_flow(flow_metrics=tgen_flow_stats,
                          pause_flow_name=PAUSE_FLW_NAME)

    if (test_def['background_traffic'] and test_def['verify_flows']):
        if snappi_extra_params.gen_background_traffic:
            # Verify background flows
            verify_background_flow(flow_metrics=tgen_flow_stats,
                                   speed_gbps=speed_gbps,
                                   tolerance=TOLERANCE_THRESHOLD,
                                   snappi_extra_params=snappi_extra_params)

    # Verify basic test flows metrics from ixia
    if (test_def['verify_flows']):
        verify_basic_test_flow(flow_metrics=tgen_flow_stats,
                               speed_gbps=speed_gbps,
                               tolerance=TOLERANCE_THRESHOLD,
                               test_flow_pause=test_traffic_pause,
                               snappi_extra_params=snappi_extra_params)

    if (test_traffic_pause and test_def['verify_flows']):
        verify_pause_frame_count_dut(rx_dut=ingress_duthost,
                                     tx_dut=egress_duthost,
                                     test_traffic_pause=test_traffic_pause,
                                     global_pause=global_pause,
                                     snappi_extra_params=snappi_extra_params)

    # Verify in flight TX lossless packets do not leave the DUT when traffic is expected
    # to be paused, or leave the DUT when the traffic is not expected to be paused
    if (test_traffic_pause and test_def['enable_pfcwd_drop']):
        verify_egress_queue_frame_count(duthost=egress_duthost,
                                        switch_flow_stats=switch_flow_stats,
                                        test_traffic_pause=test_traffic_pause,
                                        snappi_extra_params=snappi_extra_params)
