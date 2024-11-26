import logging
import time
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts             # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     snappi_api                                                                                     # noqa: F401
from tests.common.snappi_tests.snappi_helpers import get_dut_port_id
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector, config_wred, \
    enable_ecn, config_ingress_lossless_buffer_alpha, stop_pfcwd, disable_packet_aging,\
    config_capture_pkt, traffic_flow_mode, calc_pfc_pause_flow_rate  # noqa: F401
from tests.common.snappi_tests.read_pcap import get_ipv4_pkts
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config, generate_test_flows, \
    generate_pause_flows, run_traffic                                       # noqa: F401
import json

logger = logging.getLogger(__name__)

EXP_DURATION_SEC = 1
DATA_START_DELAY_SEC = 0.1
SNAPPI_POLL_DELAY_SEC = 2
PAUSE_FLOW_NAME = 'Pause Storm'
DATA_FLOW_NAME = 'Data Flow'


def get_npu_voq_queue_counters(duthost, interface, priority):

    asic_namespace_string = ""
    if duthost.is_multi_asic:
        asic = duthost.get_port_asic_instance(interface)
        asic_namespace_string = " -n " + asic.namespace

    full_line = "".join(duthost.shell(
        "show platform npu voq queue_counters -t {} -i {} -d{}".
        format(priority, interface, asic_namespace_string))['stdout_lines'])
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


def verify_ecn_counters_for_flow_percent(ecn_counters, test_flow_percent):

    # verify that each flow had packets
    init_ctr_3, post_ctr_3 = ecn_counters[0]
    init_ctr_4, post_ctr_4 = ecn_counters[1]
    flow3_total = post_ctr_3['SAI_QUEUE_STAT_PACKETS'] - init_ctr_3['SAI_QUEUE_STAT_PACKETS']

    drop_ctr_3 = post_ctr_3['SAI_QUEUE_STAT_DROPPED_PACKETS'] -\
        init_ctr_3['SAI_QUEUE_STAT_DROPPED_PACKETS']
    wred_drop_ctr_3 = post_ctr_3['SAI_QUEUE_STAT_WRED_DROPPED_PACKETS'] -\
        init_ctr_3['SAI_QUEUE_STAT_WRED_DROPPED_PACKETS']

    drop_ctr_4 = post_ctr_4['SAI_QUEUE_STAT_DROPPED_PACKETS'] -\
        init_ctr_4['SAI_QUEUE_STAT_DROPPED_PACKETS']
    wred_drop_ctr_4 = post_ctr_4['SAI_QUEUE_STAT_WRED_DROPPED_PACKETS'] -\
        init_ctr_4['SAI_QUEUE_STAT_WRED_DROPPED_PACKETS']

    pytest_assert(drop_ctr_3 == 0 and wred_drop_ctr_3 == 0, 'Queue 3 Drop not expected')

    pytest_assert(drop_ctr_4 == 0 and wred_drop_ctr_4 == 0, 'Queue 4 Drop not expected')

    pytest_assert(flow3_total > 0,
                  'Queue 3 counters at start {} at end {} did not increment'.format(
                   init_ctr_3['SAI_QUEUE_STAT_PACKETS'], post_ctr_3['SAI_QUEUE_STAT_PACKETS']))

    flow4_total = post_ctr_4['SAI_QUEUE_STAT_PACKETS'] - init_ctr_4['SAI_QUEUE_STAT_PACKETS']

    pytest_assert(flow4_total > 0,
                  'Queue 4 counters at start {} at end {} did not increment'.format(
                   init_ctr_4['SAI_QUEUE_STAT_PACKETS'], post_ctr_4['SAI_QUEUE_STAT_PACKETS']))

    flow3_ecn = post_ctr_3['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS'] -\
        init_ctr_3['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS']
    flow4_ecn = post_ctr_4['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS'] -\
        init_ctr_4['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS']

    if sum(test_flow_percent) < 100:
        pytest_assert(
                        flow3_ecn == 0,
                        'Must have no ecn marked packets on flow 3 without congestion, percent {}'.
                        format(test_flow_percent))
        pytest_assert(
                        flow4_ecn == 0,
                        'Must have no ecn marked packets on flow 4 without congestion, percent {}'.
                        format(test_flow_percent))
    elif sum(test_flow_percent) >= 100:
        if test_flow_percent[0] > 50:
            pytest_assert(
                            flow3_ecn > 0,
                            'Must have ecn marked packets on flow 3, percent {}'.
                            format(test_flow_percent))

        if test_flow_percent[1] > 50:
            pytest_assert(
                            flow4_ecn > 0,
                            'Must have ecn marked packets on flow 4, percent {}'.
                            format(test_flow_percent))

        if test_flow_percent[0] < 50:
            pytest_assert(
                            flow3_ecn == 0,
                            'Must not have ecn marked packets on flow 3, percent {}'.
                            format(test_flow_percent))

        if test_flow_percent[1] < 50:
            pytest_assert(
                            flow4_ecn == 0,
                            'Must not have ecn marked packets on flow 4, percent {}'.
                            format(test_flow_percent))

        if test_flow_percent[0] == 50 and test_flow_percent[1] == 50:
            pytest_assert(
                            flow3_ecn > 0 and flow4_ecn > 0,
                            'Must have ecn marked packets on flows 3, 4, percent {}'.
                            format(test_flow_percent))


def run_ecn_test(api,
                 testbed_config,
                 port_config_list,
                 conn_data,
                 fanout_data,
                 dut_port,
                 lossless_prio,
                 prio_dscp_map,
                 iters,
                 snappi_extra_params=None):
    """
    Run multidut ECN test

    Args:
        api (obj): SNAPPI session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        dut_port (str): DUT port to test
        lossless_prio (int): lossless priority
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        Return captured IP packets (list of list)
    """

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    # Traffic flow:
    # tx_port (TGEN) --- ingress DUT --- egress DUT --- rx_port (TGEN)

    rx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[0]
    egress_duthost = rx_port['duthost']

    tx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[1]
    ingress_duthost = tx_port['duthost']

    pytest_assert(testbed_config is not None, 'Failed to get L2/3 testbed config')

    logger.info("Stopping PFC watchdog")
    stop_pfcwd(egress_duthost, rx_port['asic_value'])
    stop_pfcwd(ingress_duthost, tx_port['asic_value'])
    logger.info("Disabling packet aging if necessary")
    disable_packet_aging(egress_duthost)
    disable_packet_aging(ingress_duthost)

    # Configure WRED/ECN thresholds
    logger.info("Configuring WRED and ECN thresholds")
    config_result = config_wred(host_ans=egress_duthost,
                                kmin=snappi_extra_params.ecn_params["kmin"],
                                kmax=snappi_extra_params.ecn_params["kmax"],
                                pmax=snappi_extra_params.ecn_params["pmax"])
    pytest_assert(config_result is True, 'Failed to configure WRED/ECN at the DUT')
    config_result = config_wred(host_ans=ingress_duthost,
                                kmin=snappi_extra_params.ecn_params["kmin"],
                                kmax=snappi_extra_params.ecn_params["kmax"],
                                pmax=snappi_extra_params.ecn_params["pmax"])
    pytest_assert(config_result is True, 'Failed to configure WRED/ECN at the DUT')

    # Enable ECN marking
    logger.info("Enabling ECN markings")
    pytest_assert(enable_ecn(host_ans=egress_duthost, prio=lossless_prio), 'Unable to enable ecn')
    pytest_assert(enable_ecn(host_ans=ingress_duthost, prio=lossless_prio), 'Unable to enable ecn')

    config_result = config_ingress_lossless_buffer_alpha(host_ans=egress_duthost,
                                                         alpha_log2=3)

    pytest_assert(config_result is True, 'Failed to configure PFC threshold to 8')
    config_result = config_ingress_lossless_buffer_alpha(host_ans=ingress_duthost,
                                                         alpha_log2=3)

    pytest_assert(config_result is True, 'Failed to configure PFC threshold to 8')

    # Get the ID of the port to test
    port_id = get_dut_port_id(dut_hostname=egress_duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Failed to get ID for port {}'.format(dut_port))

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])

    # Generate base traffic config
    port_id = 0
    logger.info("Generating base flow config")
    snappi_extra_params.base_flow_config = setup_base_traffic_config(testbed_config=testbed_config,
                                                                     port_config_list=port_config_list,
                                                                     port_id=port_id)

    logger.info("Setting test flow config params")
    snappi_extra_params.traffic_flow_config.data_flow_config.update({
            "flow_name": DATA_FLOW_NAME,
            "flow_rate_percent": 100,
            "flow_delay_sec": DATA_START_DELAY_SEC,
            "flow_traffic_type": traffic_flow_mode.FIXED_PACKETS
        })

    logger.info("Setting pause flow config params")
    snappi_extra_params.traffic_flow_config.pause_flow_config = {
        "flow_name": PAUSE_FLOW_NAME,
        "flow_dur_sec": EXP_DURATION_SEC,
        "flow_rate_percent": None,
        "flow_rate_pps": calc_pfc_pause_flow_rate(speed_gbps),
        "flow_rate_bps": None,
        "flow_pkt_size": 64,
        "flow_pkt_count": None,
        "flow_delay_sec": 0,
        "flow_traffic_type": traffic_flow_mode.FIXED_DURATION
        }

    # Generate traffic config of one test flow and one pause storm
    logger.info("Generating test flows")
    generate_test_flows(testbed_config=testbed_config,
                        test_flow_prio_list=[lossless_prio],
                        prio_dscp_map=prio_dscp_map,
                        snappi_extra_params=snappi_extra_params)

    logger.info("Generating pause flows")
    generate_pause_flows(testbed_config=testbed_config,
                         pause_prio_list=[lossless_prio],
                         global_pause=False,
                         snappi_extra_params=snappi_extra_params)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

    logger.info("Setting packet capture port to {}".format(testbed_config.ports[port_id].name))
    snappi_extra_params.packet_capture_ports = [testbed_config.ports[port_id].name]

    result = []
    logger.info("Running {} iteration(s)".format(iters))
    for i in range(iters):
        logger.info("Running iteration {}".format(i))
        snappi_extra_params.packet_capture_file = "ECN_cap-{}".format(i)
        logger.info("Packet capture file: {}.pcapng".format(snappi_extra_params.packet_capture_file))

        config_capture_pkt(testbed_config=testbed_config,
                           port_names=snappi_extra_params.packet_capture_ports,
                           capture_type=snappi_extra_params.packet_capture_type,
                           capture_name=snappi_extra_params.packet_capture_file)

        logger.info("Running traffic")
        run_traffic(duthost=egress_duthost,
                    api=api,
                    config=testbed_config,
                    data_flow_names=data_flow_names,
                    all_flow_names=all_flow_names,
                    exp_dur_sec=EXP_DURATION_SEC,
                    snappi_extra_params=snappi_extra_params)

        result.append(get_ipv4_pkts(snappi_extra_params.packet_capture_file + ".pcapng"))

    return result


def toggle_dut_port_state(api):
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


def run_ecn_marking_port_toggle_test(
                                    api,
                                    testbed_config,
                                    port_config_list,
                                    dut_port,
                                    test_prio_list,
                                    prio_dscp_map,
                                    snappi_extra_params=None):

    """
    Run a ECN test
    Args:
        api (obj): snappi session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        dut_port (str): DUT port to test
        test_prio_list (list): priorities of test flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
        N/A
    """

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')
    pytest_assert(len(test_prio_list) >= 2, 'Must have atleast two lossless priorities')

    test_flow_percent = [99.98] * len(test_prio_list)

    TEST_FLOW_NAME = ['Test Flow 3', 'Test Flow 4']
    DATA_FLOW_PKT_SIZE = 1350
    DATA_FLOW_DURATION_SEC = 2
    DATA_FLOW_DELAY_SEC = 1

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    # Traffic flow:
    # tx_port (TGEN) --- ingress DUT --- egress DUT --- rx_port (TGEN)

    rx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[0]
    egress_duthost = rx_port['duthost']

    duthost = egress_duthost

    init_ctr_3 = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[0])
    init_ctr_4 = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[1])

    port_id = 0
    # Generate base traffic config
    base_flow_config1 = setup_base_traffic_config(testbed_config=testbed_config,
                                                  port_config_list=port_config_list,
                                                  port_id=port_id)
    port_config_list2 = [x for x in port_config_list if x != base_flow_config1['tx_port_config']]
    base_flow_config2 = setup_base_traffic_config(testbed_config=testbed_config,
                                                  port_config_list=port_config_list2,
                                                  port_id=port_id)

    # Create a dictionary with priorities as keys and flow rates as values
    flow_rate_dict = {
        prio: round(flow / len(test_prio_list), 2) for prio, flow in zip(test_prio_list, test_flow_percent)
    }

    snappi_extra_params.base_flow_config = base_flow_config1

    # Set default traffic flow configs if not set
    if snappi_extra_params.traffic_flow_config.data_flow_config is None:
        snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_name": TEST_FLOW_NAME[0],
            "flow_dur_sec": DATA_FLOW_DURATION_SEC,
            "flow_rate_percent": flow_rate_dict,
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
                        snappi_extra_params=snappi_extra_params)

    snappi_extra_params.base_flow_config = base_flow_config2

    snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_name": TEST_FLOW_NAME[1],
            "flow_dur_sec": DATA_FLOW_DURATION_SEC,
            "flow_rate_percent": flow_rate_dict,
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
                        snappi_extra_params=snappi_extra_params)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

    # Clear PFC and queue counters before traffic run
    duthost.command("sonic-clear pfccounters")
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

    toggle_dut_port_state(api)

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


def run_ecn_marking_test(api,
                         testbed_config,
                         port_config_list,
                         dut_port,
                         test_prio_list,
                         prio_dscp_map,
                         test_flow_percent,
                         snappi_extra_params=None):

    """
    Run a ECN test
    Args:
        api (obj): snappi session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        dut_port (str): DUT port to test
        test_prio_list (list): priorities of test flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic

    Returns:
        N/A
    """

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')
    pytest_assert(len(test_prio_list) >= 2, 'Must have atleast two lossless priorities')

    pytest_assert(len(test_flow_percent) == len(test_prio_list),
                  "The length of test_flow_percent must match the length of test_prio_list")

    TEST_FLOW_NAME = ['Test Flow 3', 'Test Flow 4']
    DATA_FLOW_PKT_SIZE = 1350
    DATA_FLOW_DURATION_SEC = 2
    DATA_FLOW_DELAY_SEC = 1

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    # Traffic flow:
    # tx_port (TGEN) --- ingress DUT --- egress DUT --- rx_port (TGEN)

    rx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[0]
    egress_duthost = rx_port['duthost']

    duthost = egress_duthost

    init_ctr_3 = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[0])
    init_ctr_4 = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[1])

    port_id = 0
    # Generate base traffic config
    base_flow_config1 = setup_base_traffic_config(testbed_config=testbed_config,
                                                  port_config_list=port_config_list,
                                                  port_id=port_id)
    port_config_list2 = [x for x in port_config_list if x != base_flow_config1['tx_port_config']]
    base_flow_config2 = setup_base_traffic_config(testbed_config=testbed_config,
                                                  port_config_list=port_config_list2,
                                                  port_id=port_id)

    # Create a dictionary with priorities as keys and flow rates as values
    flow_rate_dict = {
        prio: round(flow / len(test_prio_list), 2) for prio, flow in zip(test_prio_list, test_flow_percent)
    }

    snappi_extra_params.base_flow_config = base_flow_config1

    # Set default traffic flow configs if not set
    if snappi_extra_params.traffic_flow_config.data_flow_config is None:
        snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_name": TEST_FLOW_NAME[0],
            "flow_dur_sec": DATA_FLOW_DURATION_SEC,
            "flow_rate_percent": flow_rate_dict,
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
                        snappi_extra_params=snappi_extra_params)

    snappi_extra_params.base_flow_config = base_flow_config2

    snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_name": TEST_FLOW_NAME[1],
            "flow_dur_sec": DATA_FLOW_DURATION_SEC,
            "flow_rate_percent": flow_rate_dict,
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
                        snappi_extra_params=snappi_extra_params)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

    # Clear PFC and queue counters before traffic run
    duthost.command("sonic-clear pfccounters")
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

    verify_ecn_counters_for_flow_percent(ecn_counters, test_flow_percent)
