import logging
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts # noqa F401
from tests.common.snappi_tests.snappi_helpers import get_dut_port_id
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector,\
    get_lossless_buffer_size, get_pg_dropped_packets,\
    stop_pfcwd, disable_packet_aging, sec_to_nanosec,\
    get_pfc_frame_count, packet_capture, config_capture_pkt,\
    traffic_flow_mode, calc_pfc_pause_flow_rate # noqa F401
from tests.common.snappi_tests.port import select_ports, select_tx_port # noqa F401
from tests.common.snappi_tests.snappi_helpers import wait_for_arp # noqa F401
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config, generate_test_flows,\
    run_traffic

from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
import json


logger = logging.getLogger(__name__)

DATA_FLOW_PKT_SIZE = 1024
DATA_FLOW_DURATION_SEC = 2
DATA_FLOW_DELAY_SEC = 1
TEST_FLOW_NAME = ['Test Flow 3', 'Test Flow 4']
PAUSE_FLOW_NAME = 'Pause Storm'


def get_npu_voq_queue_counters(duthost, interface, priority):
    full_line = "".join(duthost.shell(
        "show platform npu voq queue_counters -t {} -i {} -d".
        format(priority, interface))['stdout_lines'])
    dict_output = json.loads(full_line)
    for entry, value in zip(dict_output['stats_name'], dict_output['counters']):
        dict_output[entry] = value

    return dict_output


def verify_ecn_counters(ecn_counters, link_state_toggled=False):

    toggle_msg = " post link state toggle" if link_state_toggled else ""
    # verify that each flow had packets
    init_ctr_3, post_ctr_3 = ecn_counters[0]
    init_ctr_4, post_ctr_4 = ecn_counters[1]
    flow3_total = post_ctr_3['SAI_QUEUE_STAT_PACKETS'] - init_ctr_3['SAI_QUEUE_STAT_PACKETS']

    pytest_assert(flow3_total > 0,
                  'Queue 3 counters at start {} at end {} did not increment{}'.format(
                   init_ctr_3['SAI_QUEUE_STAT_PACKETS'], post_ctr_3['SAI_QUEUE_STAT_PACKETS'], toggle_msg))

    flow4_total = post_ctr_4['SAI_QUEUE_STAT_PACKETS'] - init_ctr_4['SAI_QUEUE_STAT_PACKETS']

    pytest_assert(flow4_total > 0,
                  'Queue 4 counters at start {} at end {} did not increment{}'.format(
                   init_ctr_4['SAI_QUEUE_STAT_PACKETS'], post_ctr_4['SAI_QUEUE_STAT_PACKETS'], toggle_msg))

    flow3_ecn = post_ctr_3['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS'] -\
        init_ctr_3['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS']
    flow4_ecn = post_ctr_4['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS'] -\
        init_ctr_4['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS']

    pytest_assert(flow3_ecn > 0,
                  'Must have ecn marked packets on flow 3{}'.
                  format(toggle_msg))

    pytest_assert(flow4_ecn > 0,
                  'Must have ecn marked packets on flow 4{}'.
                  format(toggle_msg))


# line rate percent for TC 3, 4 from tx port a, b
# ecn counter is per TC, both TC has same dwrr weight
def run_ecn_test_cisco8000(api,
                           testbed_config,
                           port_config_list,
                           conn_data,
                           fanout_data,
                           duthost,
                           dut_port,
                           test_prio_list,
                           prio_dscp_map,
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
        test_prio_list (list): priorities of test flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
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
    base_flow_config1 = setup_base_traffic_config(testbed_config=testbed_config,
                                                  port_config_list=port_config_list,
                                                  port_id=port_id)
    port_config_list2 = [x for x in port_config_list if x != base_flow_config1['tx_port_config']]
    base_flow_config2 = setup_base_traffic_config(testbed_config=testbed_config,
                                                  port_config_list=port_config_list2,
                                                  port_id=port_id)

    # Generate test flow config
    traffic_rate = 99.98
    test_flow_rate_percent = int(traffic_rate / len(test_prio_list))

    snappi_extra_params.base_flow_config = base_flow_config1

    # Set default traffic flow configs if not set
    if snappi_extra_params.traffic_flow_config.data_flow_config is None:
        snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_name": TEST_FLOW_NAME[0],
            "flow_dur_sec": DATA_FLOW_DURATION_SEC,
            "flow_rate_percent": test_flow_rate_percent,
            "flow_rate_pps": None,
            "flow_rate_bps": None,
            "flow_pkt_size": DATA_FLOW_PKT_SIZE,
            "flow_pkt_count": None,
            "flow_delay_sec": DATA_FLOW_DELAY_SEC,
            "flow_traffic_type": traffic_flow_mode.FIXED_DURATION
        }

    generate_test_flows(testbed_config=testbed_config,
                        test_flow_prio_list=test_prio_list,
                        prio_dscp_map=prio_dscp_map,
                        snappi_extra_params=snappi_extra_params,
                        number_of_streams=2)

    snappi_extra_params.base_flow_config = base_flow_config2

    snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_name": TEST_FLOW_NAME[1],
            "flow_dur_sec": DATA_FLOW_DURATION_SEC,
            "flow_rate_percent": test_flow_rate_percent,
            "flow_rate_pps": None,
            "flow_rate_bps": None,
            "flow_pkt_size": DATA_FLOW_PKT_SIZE,
            "flow_pkt_count": None,
            "flow_delay_sec": DATA_FLOW_DELAY_SEC,
            "flow_traffic_type": traffic_flow_mode.FIXED_DURATION
        }
    generate_test_flows(testbed_config=testbed_config,
                        test_flow_prio_list=test_prio_list,
                        prio_dscp_map=prio_dscp_map,
                        snappi_extra_params=snappi_extra_params,
                        number_of_streams=2)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

    # Clear PFC and queue counters before traffic run
    duthost.command("pfcstat -c")
    duthost.command("sonic-clear queuecounters")

    """ Run traffic """
    _tgen_flow_stats, _switch_flow_stats, _in_flight_flow_metrics = run_traffic(
                                                                duthost,
                                                                api=api,
                                                                config=testbed_config,
                                                                data_flow_names=data_flow_names,
                                                                all_flow_names=all_flow_names,
                                                                exp_dur_sec=DATA_FLOW_DURATION_SEC +
                                                                DATA_FLOW_DELAY_SEC,
                                                                snappi_extra_params=snappi_extra_params)

    post_ctr_3 = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[0])
    post_ctr_4 = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[1])

    ecn_counters = [
        (init_ctr_3, post_ctr_3),
        (init_ctr_4, post_ctr_4)
    ]

    verify_ecn_counters(ecn_counters)

    # Get the current configuration
    config = api.get_config()
    # Collect all port names
    port_names = [port.name for port in config.ports]
    # Create a link state object for all ports
    link_state = api.link_state()
    # Apply the state to all ports
    link_state.port_names = port_names
    # Set all ports down (shut)
    link_state.state = link_state.DOWN
    api.set_link_state(link_state)
    logger.info("All Snappi ports are set to DOWN")
    time.sleep(0.2)
    # Unshut all ports
    link_state.state = link_state.UP
    api.set_link_state(link_state)
    logger.info("All Snappi ports are set to UP")

    init_ctr_3 = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[0])
    init_ctr_4 = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[1])

    """ Run traffic """
    _tgen_flow_stats, _switch_flow_stats, _in_flight_flow_metrics = run_traffic(
                                                                duthost,
                                                                api=api,
                                                                config=testbed_config,
                                                                data_flow_names=data_flow_names,
                                                                all_flow_names=all_flow_names,
                                                                exp_dur_sec=DATA_FLOW_DURATION_SEC +
                                                                DATA_FLOW_DELAY_SEC,
                                                                snappi_extra_params=snappi_extra_params)

    post_ctr_3 = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[0])
    post_ctr_4 = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[1])

    ecn_counters = [
        (init_ctr_3, post_ctr_3),
        (init_ctr_4, post_ctr_4)
    ]

    verify_ecn_counters(ecn_counters, link_state_toggled=True)
