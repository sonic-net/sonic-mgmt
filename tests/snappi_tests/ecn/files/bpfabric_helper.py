import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts             # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     snappi_api                                                                                     # noqa: F401
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector, config_wred, \
    enable_ecn, config_ingress_lossless_buffer_alpha, stop_pfcwd, disable_packet_aging,\
    config_capture_pkt, traffic_flow_mode, calc_pfc_pause_flow_rate, get_all_port_stats  # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config, generate_test_flows, \
    generate_pause_flows, run_traffic                                       # noqa: F401
from tests.snappi_tests.files.helper import get_fabric_mapping, load_port_stats, \
    infer_ecmp_backplane_ports, set_cir_cisco_8000, get_npu_voq_queue_counters, compute_expected_packets
import time


logger = logging.getLogger(__name__)

DATA_FLOW_PKT_SIZE = 1350
DATA_FLOW_DURATION_SEC = 2
DATA_FLOW_DELAY_SEC = 1
DATA_FLOW_NAME = 'Data Flow'
PAUSE_FLOW_NAME = 'Pause Storm'


def verify_ecn_marking_counters(ecn_counters, lossless_prio, intf):
    # verify that each flow had packets
    init_ctr, post_ctr = ecn_counters[0]

    flow_total = post_ctr['SAI_QUEUE_STAT_PACKETS'] - init_ctr['SAI_QUEUE_STAT_PACKETS']

    pytest_assert(flow_total > 0,
                  'Queue {} counters at start {} at end {} did not increment of {}'.format(
                      lossless_prio, init_ctr['SAI_QUEUE_STAT_PACKETS'], post_ctr['SAI_QUEUE_STAT_PACKETS'], intf))

    flow_ecn = post_ctr['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS'] -\
        init_ctr['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS']

    pytest_assert(flow_ecn > 0,
                  'Must have ecn marked packets on queue {} of {}'.format(lossless_prio, intf))


def _generate_traffic_config(testbed_config,
                             snappi_extra_params,
                             port_config_list,
                             test_prio_list,
                             test_flow_percent,
                             prio_dscp_map,
                             congested=False):
    TEST_FLOW_NAME = DATA_FLOW_NAME + ' ' + str(test_prio_list[0])

    port_id = 0
    # Generate base traffic config
    base_flow_config1 = setup_base_traffic_config(testbed_config=testbed_config,
                                                  port_config_list=port_config_list,
                                                  port_id=port_id)

    # Create a dictionary with priorities as keys and flow rates as values
    flow_rate_dict = {
        prio: round(flow / len(test_prio_list), 2) for prio, flow in zip(test_prio_list, test_flow_percent)
    }

    snappi_extra_params.base_flow_config = base_flow_config1

    # Set default traffic flow configs if not set
    if snappi_extra_params.traffic_flow_config.data_flow_config is None:
        snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_name": TEST_FLOW_NAME,
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
                        snappi_extra_params=snappi_extra_params,
                        congested=congested,
                        number_of_streams=1)


def get_traffic_path(
                    api,
                    testbed_config,
                    port_config_list,
                    dut_port,
                    test_prio_list,
                    prio_dscp_map,
                    snappi_extra_params):

    """
    Returns:
        list: Returns traffic path [ingress_port, tx_bp, fabric_rx, fabric_tx, rx_bp, egress_port]
    """

    test_flow_percent = [49] * len(test_prio_list)

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    # Traffic flow:
    # tx_port (TGEN) --- ingress DUT ---Fabric---- egress DUT --- rx_port (TGEN)

    rx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[0]
    egress_duthost = rx_port['duthost']

    tx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[1]
    ingress_duthost = tx_port['duthost']

    # Append the duthost here for run_traffic to clear its counters
    snappi_extra_params.multi_dut_params.ingress_duthosts.append(ingress_duthost)
    snappi_extra_params.multi_dut_params.egress_duthosts.append(egress_duthost)

    duthost = egress_duthost

    _generate_traffic_config(testbed_config, snappi_extra_params,
                             port_config_list, test_prio_list,
                             test_flow_percent, prio_dscp_map)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])

    # Find the expected packets for the given traffic duration and flow percent.
    # This helps find the bp interfaces involved in the traffic path more accurately
    pkt_threshold = compute_expected_packets(speed_gbps * 10**9 * test_flow_percent[0]/100,
                                             DATA_FLOW_PKT_SIZE, DATA_FLOW_DURATION_SEC)

    """ Run traffic """
    _, _, _ = run_traffic(
                            duthost,
                            api=api,
                            config=testbed_config,
                            data_flow_names=data_flow_names,
                            all_flow_names=all_flow_names,
                            exp_dur_sec=DATA_FLOW_DURATION_SEC +
                            DATA_FLOW_DELAY_SEC,
                            snappi_extra_params=snappi_extra_params)

    # get all the port stats
    ingress_stats = get_all_port_stats(ingress_duthost)
    egress_stats = get_all_port_stats(egress_duthost)

    # Find the active data path interfaces using the expected pkt threshold.
    ingress_active_interfaces = load_port_stats(ingress_stats, pkt_threshold, direction="tx")
    egress_active_interfaces = load_port_stats(egress_stats, pkt_threshold, direction="rx")

    # Find the fabric mapping from the CLI
    ingress_fabric_mapping = get_fabric_mapping(ingress_duthost)
    egress_fabric_mapping = get_fabric_mapping(egress_duthost)

    # Infer the traffic path from ingress to egress port via BP and Fabric port
    traffic_paths = infer_ecmp_backplane_ports(ingress_active_interfaces, egress_active_interfaces,
                                               snappi_extra_params.multi_dut_params.multi_dut_ports[1]['peer_port'],
                                               dut_port, ingress_fabric_mapping, egress_fabric_mapping)

    pytest_assert(traffic_paths, "Unable to find traffic path for the given ingress and egress port")

    logger.info("Traffic paths {}".format(traffic_paths))
    return traffic_paths


def adjust_shaper_and_verify(dut, egress_intfs, test_prio_list, api):
    egress_asic_map = {}

    # Create a map of asic instance and egress ports involved in the traffic path
    for intf in egress_intfs:
        asic_instance = dut.get_port_asic_instance(intf)
        if asic_instance not in egress_asic_map:
            egress_asic_map[asic_instance] = []

        egress_asic_map[asic_instance].append(intf)

    try:
        # Iterate over the egress port map and call set_cir_cisco_8000
        for asic_instance, intf_list in egress_asic_map.items():
            # Set the shaper to 5GB to induce congestion on the egress ports
            set_cir_cisco_8000(dut, intf_list, asic_instance, speed=5 * 1000 * 1000 * 1000)

        queue_counters = {}
        for intf in egress_intfs:
            init_ctr = get_npu_voq_queue_counters(dut, intf, test_prio_list[0])

            queue_counters[intf] = init_ctr

        # Start traffic again
        cs = api.control_state()
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
        api.set_control_state(cs)

        time.sleep(DATA_FLOW_DURATION_SEC + DATA_FLOW_DELAY_SEC)

        # Stop traffic
        cs = api.control_state()
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
        api.set_control_state(cs)

        for intf in egress_intfs:
            post_ctr = get_npu_voq_queue_counters(dut, intf, test_prio_list[0])

            init_ctr = queue_counters[intf]

            ecn_counters = [
                (init_ctr, post_ctr)
            ]

            verify_ecn_marking_counters(ecn_counters, test_prio_list[0], intf)
    finally:
        # Iterate over the fabric egress port map and call set_cir_cisco_8000
        for asic_instance, intf_list in egress_asic_map.items():
            # Reset the shaper on the egress ports
            set_cir_cisco_8000(dut, intf_list, asic_instance)


def run_fabric_ecn_marking_test(api,
                                testbed_config,
                                port_config_list,
                                dut_port,
                                test_prio_list,
                                prio_dscp_map,
                                supervisor_dut,
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
        test_prio_list (list): priority of test flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        supervisor_dut (duthost): dutHost obj for supervisor in case of multi-DUT
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic

    Returns:
        N/A
    """

    pytest_assert(testbed_config is not None, 'Failed to get L2/3 testbed config')
    pytest_assert(len(test_prio_list) >= 1, 'Must have atleast one lossless priorities')

    traffic_paths = get_traffic_path(api,
                                     testbed_config, port_config_list,
                                     dut_port, test_prio_list, prio_dscp_map, snappi_extra_params)

    # Get list of Fabric egress ports only
    fabric_egress = [path[3] for path in traffic_paths]

    adjust_shaper_and_verify(supervisor_dut, fabric_egress, test_prio_list, api)


def run_backplane_ecn_marking_test(
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
        test_prio_list (list): priority of test flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic

    Returns:
        N/A
    """

    pytest_assert(testbed_config is not None, 'Failed to get L2/3 testbed config')
    pytest_assert(len(test_prio_list) >= 1, 'Must have atleast one lossless priorities')

    traffic_paths = get_traffic_path(api,
                                     testbed_config, port_config_list,
                                     dut_port, test_prio_list, prio_dscp_map, snappi_extra_params)

    # Get list of backplane egress ports only
    backplane_egress = [path[1] for path in traffic_paths]

    tx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[1]
    ingress_duthost = tx_port['duthost']

    adjust_shaper_and_verify(ingress_duthost, backplane_egress, test_prio_list, api)
