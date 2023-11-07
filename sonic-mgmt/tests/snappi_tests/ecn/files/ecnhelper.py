import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts # noqa F401
from tests.common.snappi_tests.snappi_helpers import get_dut_port_id
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector,\
    get_lossless_buffer_size, get_pg_dropped_packets,\
    stop_pfcwd, disable_packet_aging, sec_to_nanosec,\
    get_pfc_frame_count, packet_capture, config_capture_pkt # noqa F401
from tests.common.snappi_tests.port import select_ports, select_tx_port # noqa F401
from tests.common.snappi_tests.snappi_helpers import wait_for_arp # noqa F401
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config, generate_test_flows,\
    generate_background_flows, generate_pause_flows, run_traffic, verify_pause_flow, verify_basic_test_flow,\
    verify_background_flow, verify_pause_frame_count, verify_egress_queue_frame_count, verify_in_flight_buffer_pkts,\
    verify_unset_cev_pause_frame_count
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.read_pcap import validate_pfc_frame

logger = logging.getLogger(__name__)

dut_port_config = []
PAUSE_FLOW_NAME = 'Pause Storm'
TEST_FLOW_NAME = 'Test Flow'
TEST_FLOW_AGGR_RATE_PERCENT = 45
BG_FLOW_NAME = 'Background Flow'
BG_FLOW_AGGR_RATE_PERCENT = 45
PAUSE_FLOW_DUR_BASE_SEC = 3

data_flow_pkt_size = 1024
DATA_FLOW_DURATION_SEC = 2
data_flow_delay_sec = 1
SNAPPI_POLL_DELAY_SEC = 2
TOLERANCE_THRESHOLD = 0.05
CONTINUOUS_MODE = -5
#
TEST_FLOW_NAME = ['Test Flow 3', 'Test Flow 4']

def get_npu_voq_queue_counters(duthost, interface, priority):
    full_line = "".join(duthost.shell("show platform npu voq queue_counters -t {} -i {} -d".format(priority, interface))['stdout_lines'])
    import json
    dict_output = json.loads(full_line)
    for entry,value in zip(dict_output['stats_name'], dict_output['counters']):
        dict_output[entry] = value

    return dict_output

logger = logging.getLogger(__name__)

EXP_DURATION_SEC = 1
DATA_START_DELAY_SEC = 0.1
SNAPPI_POLL_DELAY_SEC = 2
PAUSE_FLOW_NAME = 'Pause Storm'
DATA_FLOW_NAME = 'Data Flow'

# line rate percent for TC 3, 4 from tx port a, b
# ecn counter is per TC, both TC has same dwrr weight

def run_ecn_test_cisco8000(api,
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
                 test_flow_percent,
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
    pytest_assert(len(test_prio_list) >= 2, 'Must have atleast two lossless priorities')


    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    stop_pfcwd(duthost)
    disable_packet_aging(duthost)

    init_ctr_3 = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[0])
    init_ctr_4 = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[1])

    # Get the ID of the port to test
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Fail to get ID for port {}'.format(dut_port))

    # Generate base traffic config
    base_flow_config1 =  setup_base_traffic_config(testbed_config=testbed_config,
                                                   port_config_list=port_config_list,
                                                   port_id=port_id)
    port_config_list2 = [ x for x in port_config_list if x != base_flow_config1['tx_port_config'] ]
    base_flow_config2 = setup_base_traffic_config(testbed_config=testbed_config,
                                                                     port_config_list=port_config_list2,
                                                                     port_id=port_id)

    # Generate test flow config
    # Rate percent must be an integer
    test_prio_list0 = [test_prio_list[0]]
    test_flow_rate_percent = test_flow_percent[0]
    snappi_extra_params.base_flow_config = base_flow_config1
    generate_test_flows(testbed_config=testbed_config,
                        test_flow_name=TEST_FLOW_NAME[0],
                        test_flow_prio_list=test_prio_list0,
                        test_flow_rate_percent=test_flow_rate_percent,
                        test_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                        test_flow_delay_sec=data_flow_delay_sec,
                        test_flow_pkt_size=data_flow_pkt_size,
                        prio_dscp_map=prio_dscp_map,
                        snappi_extra_params=snappi_extra_params)

    test_prio_list1 = [test_prio_list[1]]
    test_flow_rate_percent = test_flow_percent[1]
    snappi_extra_params.base_flow_config = base_flow_config2
    generate_test_flows(testbed_config=testbed_config,
                        test_flow_name=TEST_FLOW_NAME[1],
                        test_flow_prio_list=test_prio_list1,
                        test_flow_rate_percent=test_flow_rate_percent,
                        test_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                        test_flow_delay_sec=data_flow_delay_sec,
                        test_flow_pkt_size=data_flow_pkt_size,
                        prio_dscp_map=prio_dscp_map,
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

    post_ctr_3 = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[0])
    post_ctr_4 = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[1])

    # verify that each flow had packets
    flow3_total = post_ctr_3['SAI_QUEUE_STAT_PACKETS'] - init_ctr_3['SAI_QUEUE_STAT_PACKETS'] 
    if test_flow_percent[0] > 0:
        pytest_assert(flow3_total > 0, 'Must have packets on queue 3')

    flow4_total = post_ctr_4['SAI_QUEUE_STAT_PACKETS'] - init_ctr_4['SAI_QUEUE_STAT_PACKETS'] 
    if test_flow_percent[1] > 0:
        pytest_assert(flow4_total  > 0, 'Must have packets on queue 4')

    flow3_ecn = post_ctr_3['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS'] - init_ctr_3['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS']
    flow4_ecn = post_ctr_4['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS'] - init_ctr_4['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS']

    if sum(test_flow_percent) < 100:
        pytest_assert(flow3_ecn == 0, 'Must have no ecn marked packets on flow 3 without congestion, percent {}'.format(test_flow_percent))
        pytest_assert(flow4_ecn == 0, 'Must have no ecn marked packets on flow 4 without congestion, percent {}'.format(test_flow_percent))
    elif sum(test_flow_percent) >= 100:
        if test_flow_percent[0] > 50:
            pytest_assert(flow3_ecn > 0, 'Must have ecn marked packets on flow 3, percent {}'.format(test_flow_percent))

        if test_flow_percent[1] > 50:
            pytest_assert(flow4_ecn > 0, 'Must have ecn marked packets on flow 4, percent {}'.format(test_flow_percent))

        if test_flow_percent[0] < 50:
            pytest_assert(flow3_ecn == 0, 'Must not have ecn marked packets on flow 3, percent {}'.format(test_flow_percent))

        if test_flow_percent[1] < 50:
            pytest_assert(flow4_ecn == 0, 'Must not have ecn marked packets on flow 4, percent {}'.format(test_flow_percent))
       
    # verify that the total packets sent match  the rate configured :test_flow_percent=[90, 15]
    flow_ratio = float(flow3_total/flow4_total)
    flow_percent_ratio = float(test_flow_percent[0] / test_flow_percent[1])
    pytest_assert(flow_ratio == flow_percent_ratio , "The packet flow ratio {}, must match flow percent ratio {}".format(flow_ratio, flow_percent_ratio))
