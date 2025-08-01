import logging
import time
import csv
import os
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts             # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     snappi_api                                                                                     # noqa: F401
from tests.common.snappi_tests.snappi_helpers import get_dut_port_id
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector, config_wred, \
    enable_ecn, config_ingress_lossless_buffer_alpha, stop_pfcwd, disable_packet_aging,\
    config_capture_pkt, traffic_flow_mode, calc_pfc_pause_flow_rate, get_pfc_frame_count  # noqa: F401
from tests.common.snappi_tests.read_pcap import get_ipv4_pkts
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config, generate_test_flows, \
    generate_pause_flows, run_traffic                                       # noqa: F401
import json
from tests.snappi_tests.files.helper import get_fabric_mapping

logger = logging.getLogger(__name__)

EXP_DURATION_SEC = 1
DATA_START_DELAY_SEC = 0.1
SNAPPI_POLL_DELAY_SEC = 2
PAUSE_FLOW_NAME = 'Pause Storm'
DATA_FLOW_NAME = 'Data Flow'


def get_npu_voq_queue_counters(duthost, interface, priority, clear=False):

    asic_namespace_string = ""
    if duthost.is_multi_asic:
        asic = duthost.get_port_asic_instance(interface)
        asic_namespace_string = " -n " + asic.namespace

    clear_cmd = ""
    if clear:
        clear_cmd = " -c"

    full_line = "".join(duthost.shell(
        "show platform npu voq queue_counters -t {} -i {} -d{}{}".
        format(priority, interface, asic_namespace_string, clear_cmd))['stdout_lines'])
    dict_output = json.loads(full_line)
    for entry, value in zip(dict_output['stats_name'], dict_output['counters']):
        dict_output[entry] = value

    return dict_output

#  When bp_fabric_ecn_marking_check is True
#
#  The traffic is flowing from short link to long link
#
# Step 1: Clear all counters  on egress, fabric, and ingress DUT
# Step 2: Send traffic for the test.
# Step 3: Verify egress port queue counter at possible congestion points.
# Step 4: If no marking,
# - check and log  backpressure
# - Fail the testcase


def clear_bp_fabric_queue_counters(ingress_fabric_mapping_dict, egress_fabric_mapping, supervisor_dut, test_prio_list):
    """
    Clears VOQ queue counters of the ingress DUT BP ports and the Fabric ports connected to the Egress DUT.
    """
    for priority in test_prio_list:
        for fabric_egress_bp in egress_fabric_mapping.values():
            get_npu_voq_queue_counters(supervisor_dut, fabric_egress_bp, priority, clear=True)

        for ingress_duthost, ingress_fabric_mappings in ingress_fabric_mapping_dict.items():
            for fabric_mapping in ingress_fabric_mappings.values():
                for lc_egress_bp in fabric_mapping.keys():
                    get_npu_voq_queue_counters(ingress_duthost, lc_egress_bp, priority, clear=True)

    logger.info("Counters cleared for ingress DUT BP ports and Fabric Egress ports")


def check_bp_fabric_ecn_marking(ingress_fabric_mapping_dict, egress_fabric_mapping, supervisor_dut, test_prio_list):
    """
    Checks for ECN marked packets across ingress and egress fabric mappings.
    Returns True if ECN marking is found, otherwise False.
    """

    all_priorities_marked = True

    for priority in test_prio_list:
        ecn_marked_for_priority = False

        ecn_marked_packets_egress = 0
        for fabric_egress_bp in egress_fabric_mapping.values():
            ctr_egress = get_npu_voq_queue_counters(supervisor_dut, fabric_egress_bp, priority)
            ecn_marked_fb = ctr_egress.get('SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS', 0)
            ecn_marked_packets_egress += ecn_marked_fb
            if ecn_marked_fb > 0:
                logging.info("ECN marking : {} on Fabric interface: {}, priority: {}".format(
                    ecn_marked_fb, fabric_egress_bp, priority))
                ecn_marked_for_priority = True

        if ecn_marked_packets_egress:
            logging.info("Total Fabric ECN marking detected: {}  on priority: {} ".format(
                ecn_marked_packets_egress, priority))

        ecn_marked_packets_ingress = 0
        for ingress_duthost, ingress_fabric_mappings in ingress_fabric_mapping_dict.items():
            for fabric_mapping in ingress_fabric_mappings.values():
                for lc_egress_bp in fabric_mapping.keys():
                    ctr_ingress = get_npu_voq_queue_counters(ingress_duthost, lc_egress_bp, priority)
                    ecn_marked_bp = ctr_ingress.get('SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS', 0)
                    ecn_marked_packets_ingress += ecn_marked_bp
                    if ecn_marked_bp > 0:
                        logging.info("ECN marking : {}  on ingress DUT {}, interface: {}, priority: {}".format(
                            ecn_marked_bp, ingress_duthost, lc_egress_bp, priority))
                        ecn_marked_for_priority = True

                if ecn_marked_packets_ingress:
                    logging.info("Total Ingress BP ECN marking detected: {}  on priority: {} ".format(
                        ecn_marked_packets_ingress, priority))

        if not ecn_marked_for_priority:
            all_priorities_marked = False

    if all_priorities_marked:
        logger.info("ECN Marking detected for all priorities")
        return True
    else:
        logger.info("ECN Marking missing for some priorities")
        return False


def verify_ecn_counters(ecn_counters, is_bp_fabric_ecn_check_required=False, link_state_toggled=False):

    toggle_msg = " post link state toggle" if link_state_toggled else ""
    # verify that each flow had packets
    init_ctr_3, post_ctr_3 = ecn_counters[0]
    init_ctr_4, post_ctr_4 = ecn_counters[1]
    flow3_total = post_ctr_3['SAI_QUEUE_STAT_PACKETS'] - init_ctr_3['SAI_QUEUE_STAT_PACKETS']
    flow4_total = post_ctr_4['SAI_QUEUE_STAT_PACKETS'] - init_ctr_4['SAI_QUEUE_STAT_PACKETS']

    logging.info("Flow 3 total packets: {}, Flow 4 total packets: {}".format(flow3_total, flow4_total))

    pytest_assert(flow3_total > 0,
                  'Queue 3 counters at start {} at end {} did not increment{}'.format(
                   init_ctr_3['SAI_QUEUE_STAT_PACKETS'], post_ctr_3['SAI_QUEUE_STAT_PACKETS'], toggle_msg))

    pytest_assert(flow4_total > 0,
                  'Queue 4 counters at start {} at end {} did not increment{}'.format(
                   init_ctr_4['SAI_QUEUE_STAT_PACKETS'], post_ctr_4['SAI_QUEUE_STAT_PACKETS'], toggle_msg))

    flow3_ecn = post_ctr_3['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS'] -\
        init_ctr_3['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS']
    flow4_ecn = post_ctr_4['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS'] -\
        init_ctr_4['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS']

    if is_bp_fabric_ecn_check_required:
        if flow3_ecn == 0:
            logging.info("ECN marking check failed on flow 3 on egress port")
            return False  # Flow 3 ECN marking failed
        elif flow4_ecn == 0:
            logging.info("ECN marking check failed on flow 4 on egress port")
            return False  # Flow 4 ECN marking failed
        else:
            logging.info("ECN marking check passed on both flow 3 and 4 on egress port")
            return True  # Both flows had ECN marked packets (success)

    pytest_assert(flow3_ecn > 0,
                  'Must have ecn marked packets on flow 3{}'.
                  format(toggle_msg))

    pytest_assert(flow4_ecn > 0,
                  'Must have ecn marked packets on flow 4{}'.
                  format(toggle_msg))
    return True


def verify_ecn_counters_for_flow_percent(
        ecn_counters,
        test_flow_percent,
        number_of_streams,
        input_port_same_asic,
        input_port_same_dut,
        single_dut):

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

        if test_flow_percent[0] > 50 and test_flow_percent[1] > 50:
            pytest_assert(
                            flow3_ecn > 0 and flow4_ecn > 0,
                            'Must have ecn marked packets on flows 3, 4, percent {}'.
                            format(test_flow_percent))
            percent3_mark = round(float(flow3_ecn/flow3_total), 2) * 100
            percent4_mark = round(float(flow4_ecn/flow4_total), 2) * 100
            flow_mark_diff = int(abs(percent3_mark - percent4_mark))
            logging.info(
                "Stream count {}, inputs on {} asic, inputs on {} dut, "
                "flow 3 percent {}, ecn {}, flow 4 percent {}, ecn {}, "
                "flow_mark_diff {}".format(
                    number_of_streams,
                    "same" if input_port_same_asic else "different",
                    "same" if input_port_same_dut else "different",
                    test_flow_percent[0],
                    flow3_ecn,
                    test_flow_percent[1],
                    flow4_ecn,
                    flow_mark_diff))
            if number_of_streams == 1 and input_port_same_asic and \
                    (test_flow_percent[0] == test_flow_percent[1]):
                pytest_assert(
                    flow_mark_diff <= 5,
                    "For flow rates {}: the flow marking deviation {} is more "
                    "than 5% tolerance: flow 3 ecn: {} flow 4 ecn: {}".
                    format(
                        test_flow_percent,
                        flow_mark_diff,
                        flow3_ecn,
                        flow4_ecn))
            # if number_of_streams > 1, the streams will be spread across voq from backplane ports with shallow
            #  occupancy. Restrict marking check to single dut in such a case (or relax marking check)
            elif input_port_same_dut and (number_of_streams == 1 or (number_of_streams > 1 and single_dut)):
                if test_flow_percent[0] > test_flow_percent[1]:
                    pytest_assert(
                        flow3_ecn > flow4_ecn,
                        "For flow percent {}, ecn count {} must be higher than "
                        "flow percent {}, ecn count {}".format(
                            test_flow_percent[0],
                            flow3_ecn,
                            test_flow_percent[1],
                            flow4_ecn))
                elif test_flow_percent[0] < test_flow_percent[1]:
                    pytest_assert(
                                   flow3_ecn < flow4_ecn,
                                   "For flow percent {}, ecn count {} must be lower than flow percent {}, ecn count {}".
                                   format(test_flow_percent[0], flow3_ecn, test_flow_percent[1], flow4_ecn))


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
                                pmax=snappi_extra_params.ecn_params["pmax"],
                                asic_value=rx_port['asic_value'])
    pytest_assert(config_result is True, 'Failed to configure WRED/ECN at the DUT')
    config_result = config_wred(host_ans=ingress_duthost,
                                kmin=snappi_extra_params.ecn_params["kmin"],
                                kmax=snappi_extra_params.ecn_params["kmax"],
                                pmax=snappi_extra_params.ecn_params["pmax"],
                                asic_value=tx_port['asic_value'])
    pytest_assert(config_result is True, 'Failed to configure WRED/ECN at the DUT')

    # Enable ECN marking
    logger.info("Enabling ECN markings")
    pytest_assert(enable_ecn(host_ans=egress_duthost, prio=lossless_prio), 'Unable to enable ecn')
    pytest_assert(enable_ecn(host_ans=ingress_duthost, prio=lossless_prio), 'Unable to enable ecn')

    config_result = config_ingress_lossless_buffer_alpha(host_ans=egress_duthost,
                                                         alpha_log2=3,
                                                         asic_value=rx_port['asic_value'])

    pytest_assert(config_result is True, 'Failed to configure PFC threshold to 8')
    config_result = config_ingress_lossless_buffer_alpha(host_ans=ingress_duthost,
                                                         alpha_log2=3,
                                                         asic_value=tx_port['asic_value'])

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
                        snappi_extra_params=snappi_extra_params,
                        number_of_streams=10)

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

        result.append(get_ipv4_pkts(snappi_extra_params.packet_capture_file + ".pcapng", protocol_num=17))

    return result


def toggle_dut_port_state(api):
    # Get the current configuration
    config = api.get_config()
    # Collect all port names
    port_names = [port.name for port in config.ports]
    # Create a control state object for all ports
    cs = api.control_state()
    cs.choice = cs.PORT
    cs.port.choice = cs.port.LINK
    # Apply the state to all ports
    cs.port.link.port_names = port_names
    # Set all ports down (shut)
    cs.port.link.state = cs.port.link.DOWN
    api.set_control_state(cs)
    logger.info("All Snappi ports are set to DOWN")
    time.sleep(0.2)
    # Unshut all ports
    cs.port.link.state = cs.port.link.UP
    api.set_control_state(cs)
    logger.info("All Snappi ports are set to UP")


def _generate_traffic_config(testbed_config,
                             snappi_extra_params,
                             port_config_list,
                             test_prio_list,
                             test_flow_percent,
                             prio_dscp_map,
                             number_of_streams=10,
                             congested=False):
    TEST_FLOW_NAME = ['Test Flow 3', 'Test Flow 4']
    DATA_FLOW_PKT_SIZE = 1350
    DATA_FLOW_DURATION_SEC = 2
    DATA_FLOW_DELAY_SEC = 1

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
                        snappi_extra_params=snappi_extra_params,
                        congested=congested,
                        number_of_streams=10)

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
                        snappi_extra_params=snappi_extra_params,
                        congested=congested,
                        number_of_streams=10)


def run_ecn_marking_port_toggle_test(
                                    api,
                                    testbed_config,
                                    port_config_list,
                                    dut_port,
                                    test_prio_list,
                                    prio_dscp_map,
                                    supervisor_dut=None,
                                    is_bp_fabric_ecn_check_required=False,
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
        supervisor_dut (obj): Supervisor DUT, if ECN check is required
        is_bp_fabric_ecn_check_required (bool): Flag to indicate if BP fabric ECN check is required
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
        N/A
    """

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')
    pytest_assert(len(test_prio_list) >= 2, 'Must have atleast two lossless priorities')

    test_flow_percent = [99.98] * len(test_prio_list)

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    DATA_FLOW_DURATION_SEC = 2
    DATA_FLOW_DELAY_SEC = 1

    # Traffic flow:
    # tx_port (TGEN) --- ingress DUT --- egress DUT --- rx_port (TGEN)

    rx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[0]
    egress_duthost = rx_port['duthost']

    duthost = egress_duthost

    tx_port_1 = snappi_extra_params.multi_dut_params.multi_dut_ports[1]
    ingress_duthost_1 = tx_port_1['duthost']

    tx_port_2 = snappi_extra_params.multi_dut_params.multi_dut_ports[1]
    ingress_duthost_2 = tx_port_2['duthost']

    # Append the duthost here for run_traffic to clear its counters
    snappi_extra_params.multi_dut_params.ingress_duthosts.append(ingress_duthost_1)
    snappi_extra_params.multi_dut_params.ingress_duthosts.append(ingress_duthost_2)
    snappi_extra_params.multi_dut_params.egress_duthosts.append(egress_duthost)

    # Find fabric mapping per ASIC instance
    ingress_fabric_mapping_dict = {}
    for ingress_duthost, tx_port in [(ingress_duthost_1, tx_port_1), (ingress_duthost_2, tx_port_2)]:
        asic_instance = ingress_duthost.get_port_asic_instance(tx_port['peer_port'])
        fabric_mapping = get_fabric_mapping(ingress_duthost, asic_instance)
        ingress_fabric_mapping_dict.setdefault(ingress_duthost, {})[asic_instance] = fabric_mapping

    egress_asic_instance = egress_duthost.get_port_asic_instance(rx_port['peer_port'])
    egress_fabric_mapping = get_fabric_mapping(egress_duthost, egress_asic_instance)

    _generate_traffic_config(testbed_config, snappi_extra_params,
                             port_config_list, test_prio_list,
                             test_flow_percent, prio_dscp_map)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

    link_state_toggled = False

    # Function to clear  ECN counters
    def clear_ecn_counters():
        if is_bp_fabric_ecn_check_required:
            snappi_extra_params.multi_dut_params.ingress_duthosts.append(supervisor_dut)
            clear_bp_fabric_queue_counters(ingress_fabric_mapping_dict, egress_fabric_mapping,
                                           supervisor_dut, test_prio_list)

            for priority in test_prio_list:
                get_npu_voq_queue_counters(duthost, dut_port, priority, True)

    # Function to run traffic and check ECN marking
    def run_traffic_and_check_ecn():
        """Run traffic and verify ECN marking"""
        initial_counters = {priority: get_npu_voq_queue_counters(duthost, dut_port, priority)
                            for priority in test_prio_list}

        run_traffic(
            duthost, api=api, config=testbed_config, data_flow_names=data_flow_names,
            all_flow_names=all_flow_names, exp_dur_sec=DATA_FLOW_DURATION_SEC + DATA_FLOW_DELAY_SEC,
            snappi_extra_params=snappi_extra_params
        )

        post_counters = {priority: get_npu_voq_queue_counters(duthost, dut_port, priority)
                         for priority in test_prio_list}
        ecn_counters = [(initial_counters[p], post_counters[p]) for p in test_prio_list]

        return verify_ecn_counters(ecn_counters, is_bp_fabric_ecn_check_required, link_state_toggled)

    def check_ecn_marking():
        """Check ECN marking before or after port toggle"""
        clear_ecn_counters()
        ecn_marking_verified_on_egress = run_traffic_and_check_ecn()

        if not ecn_marking_verified_on_egress:
            if not check_bp_fabric_ecn_marking(ingress_fabric_mapping_dict, egress_fabric_mapping,
                                               supervisor_dut, test_prio_list):
                # Log PFC frame counts
                for dut, tx_port in [(ingress_duthost_1, tx_port_1), (ingress_duthost_2, tx_port_2)]:
                    for priority in test_prio_list:
                        pfc_count = get_pfc_frame_count(dut, tx_port['peer_port'], priority, True)
                        logging.info("PFC Tx frame count for DUT {}, Port {}, Priority {}: {}".format(
                            dut.hostname, tx_port['peer_port'], priority, pfc_count))
                pytest_assert(False, "No ECN marking in the data path")

    # Initial ECN verification
    check_ecn_marking()

    # Toggle port state
    toggle_dut_port_state(api)

    link_state_toggled = True

    # Post toggle ECN verification
    check_ecn_marking()


def run_ecn_marking_test(api,
                         testbed_config,
                         port_config_list,
                         dut_port,
                         test_prio_list,
                         prio_dscp_map,
                         test_flow_percent,
                         number_of_streams,
                         input_port_same_asic,
                         input_port_same_dut,
                         single_dut,
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

    _generate_traffic_config(testbed_config, snappi_extra_params,
                             port_config_list, test_prio_list,
                             test_flow_percent, prio_dscp_map,
                             number_of_streams=number_of_streams)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

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

    verify_ecn_counters_for_flow_percent(
        ecn_counters,
        test_flow_percent,
        number_of_streams,
        input_port_same_asic,
        input_port_same_dut,
        single_dut)


def run_ecn_marking_with_pfc_quanta_variance(
                                        api,
                                        testbed_config,
                                        port_config_list,
                                        dut_port,
                                        test_prio_list,
                                        prio_dscp_map,
                                        test_ecn_config,
                                        log_dir=None,
                                        snappi_extra_params=None):

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')
    pytest_assert(len(test_prio_list) >= 1, 'Must have atleast two lossless priorities')

    DATA_FLOW_PKT_SIZE = 1350
    DATA_FLOW_DURATION_SEC = 5
    DATA_FLOW_DELAY_SEC = 0

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    # Traffic flow:
    # tx_port (TGEN) --- ingress DUT --- egress DUT --- rx_port (TGEN)

    rx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[0]
    egress_duthost = rx_port['duthost']

    duthost = egress_duthost

    port_id = 0
    # Generate base traffic config
    base_flow_config = setup_base_traffic_config(testbed_config=testbed_config,
                                                 port_config_list=port_config_list,
                                                 port_id=port_id)

    snappi_extra_params.base_flow_config = base_flow_config

    # Set default traffic flow configs if not set
    if snappi_extra_params.traffic_flow_config.data_flow_config is None:
        snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_name": DATA_FLOW_NAME,
            "flow_dur_sec": DATA_FLOW_DURATION_SEC,
            "flow_rate_percent": 50,
            "flow_rate_pps": None,
            "flow_rate_bps": None,
            "flow_pkt_size": DATA_FLOW_PKT_SIZE,
            "flow_pkt_count": None,
            "flow_delay_sec": DATA_FLOW_DELAY_SEC,
            "flow_traffic_type": traffic_flow_mode.FIXED_DURATION
        }

    generate_test_flows(testbed_config=testbed_config,
                        test_flow_prio_list=[test_prio_list[0]],
                        prio_dscp_map=prio_dscp_map,
                        snappi_extra_params=snappi_extra_params)

    PAUSE_FLOW_NAME = "Pause flow"

    # 10 PFC frames at 2 frames/sec.
    # The pauses caused by each PFC frame do not overlap.

    PAUSE_FLOW_PKT_COUNT = 10
    PAUSE_FLOW_DELAY_SEC = 1

    if snappi_extra_params.traffic_flow_config.pause_flow_config is None:
        snappi_extra_params.traffic_flow_config.pause_flow_config = {
            "flow_name": PAUSE_FLOW_NAME,
            "flow_dur_sec": None,
            "flow_rate_percent": None,
            "flow_rate_pps": 2,
            "flow_rate_bps": None,
            "flow_pkt_size": 64,
            "flow_pkt_count": PAUSE_FLOW_PKT_COUNT,
            "flow_delay_sec": PAUSE_FLOW_DELAY_SEC,
            "flow_traffic_type": traffic_flow_mode.FIXED_PACKETS
        }

    asic_namespace = None
    if duthost.is_multi_asic:
        asic = duthost.get_port_asic_instance(dut_port)
        asic_namespace = asic.namespace
    gmin, gmax, gdrop = test_ecn_config

    # Configure WRED/ECN thresholds
    logger.info("Configuring WRED and ECN thresholds gmin {}MB gmax {}MB gdrop {}%".format(gmin, gmax, gdrop))

    config_result = config_wred(host_ans=duthost,
                                kmin=gmin * 1024 * 1024,
                                kmax=gmax * 1024 * 1024,
                                pmax=0,
                                kdrop=gdrop,
                                asic_value=asic_namespace)

    pytest_assert(config_result is True, 'Failed to configure WRED/ECN at the DUT')

    start_quanta = 500
    end_quanta = 65000
    n = 15  # Number of quanta values

    step = (end_quanta - start_quanta) // (n - 1)
    # Generate all but the last value
    pause_quanta_list = [start_quanta + i * step for i in range(n - 1)]
    # The last value is exactly `end_quanta`
    pause_quanta_list.append(end_quanta)

    logging.info("PFC quanta list: {}".format(pause_quanta_list))

    _ = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[0], True)
    results = []
    for quanta in pause_quanta_list:
        snappi_extra_params.traffic_flow_config.pause_flow_config["flow_quanta"] = quanta

        # Remove any existing pause flow
        for index, flow in enumerate(testbed_config.flows):
            if PAUSE_FLOW_NAME in flow.name:
                testbed_config.flows.remove(index)

        # Generate pause flow config
        generate_pause_flows(testbed_config=testbed_config,
                             pause_prio_list=[test_prio_list[0]],
                             global_pause=False,
                             snappi_extra_params=snappi_extra_params)

        flows = testbed_config.flows

        all_flow_names = [flow.name for flow in flows]
        data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

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

        ctr_3 = get_npu_voq_queue_counters(duthost, dut_port, test_prio_list[0])
        stats_only = {key: ctr_3[key] for key in ctr_3['stats_name']}
        results.append((quanta, stats_only))

    file_name = "xoff_quanta_variance_results_{}_{}_{}.csv".format(gmin, gmax, gdrop)
    if log_dir:
        file_name = os.path.join(log_dir, file_name)

    with open(file_name, 'w', newline='') as csvfile:
        if results:
            first_ctr = results[0][1]
            fieldnames = ['quanta'] + list(first_ctr.keys()) + ['AVERAGE_ECN_MARKING']

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            prev_ecn_marked = 0
            for quanta, ctr in results:
                row = {'quanta': quanta}
                row.update(ctr)
                current_ecn_marked = ctr.get('SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS', 0)
                average_ecn_marking = round((current_ecn_marked - prev_ecn_marked) / PAUSE_FLOW_PKT_COUNT)
                row['AVERAGE_ECN_MARKING'] = average_ecn_marking
                prev_ecn_marked = current_ecn_marked
                writer.writerow(row)

    for i in range(len(results) - 1):
        ecn_i = results[i][1]['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS']
        ecn_i_plus_1 = results[i + 1][1]['SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS']

        if ecn_i > 0:
            pytest_assert(ecn_i_plus_1 > ecn_i,
                          "ecn marked {} at quanta {} should be less than ecn marked {} at quanta {}".
                          format(ecn_i, results[i][0], ecn_i_plus_1, results[i+1][0]))
        else:
            pytest_assert(ecn_i_plus_1 >= ecn_i,
                          "ecn marked {} at quanta {} should not be greater than ecn marked {} at quanta {}".
                          format(ecn_i, results[i][0], ecn_i_plus_1, results[i+1][0]))


def run_ecn_marking_ect_marked_pkts(
                                    api,
                                    testbed_config,
                                    port_config_list,
                                    dut_port,
                                    test_prio_list,
                                    prio_dscp_map,
                                    supervisor_dut=None,
                                    is_bp_fabric_ecn_check_required=False,
                                    snappi_extra_params=None):

    """
    Run a ECN test on congestion marker pkts
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

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    DATA_FLOW_DURATION_SEC = 2
    DATA_FLOW_DELAY_SEC = 1

    # Traffic flow:
    # tx_port (TGEN) --- ingress DUT --- egress DUT --- rx_port (TGEN)

    rx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[0]
    egress_duthost = rx_port['duthost']
    duthost = egress_duthost

    tx_port_1 = snappi_extra_params.multi_dut_params.multi_dut_ports[1]
    ingress_duthost_1 = tx_port_1['duthost']

    tx_port_2 = snappi_extra_params.multi_dut_params.multi_dut_ports[1]
    ingress_duthost_2 = tx_port_2['duthost']

    # Append the duthost here for run_traffic to clear its counters
    snappi_extra_params.multi_dut_params.ingress_duthosts.append(ingress_duthost_1)
    snappi_extra_params.multi_dut_params.ingress_duthosts.append(ingress_duthost_2)
    snappi_extra_params.multi_dut_params.egress_duthosts.append(egress_duthost)

    # Find fabric mapping per ASIC instance
    ingress_fabric_mapping_dict = {}
    for ingress_duthost, tx_port in [(ingress_duthost_1, tx_port_1), (ingress_duthost_2, tx_port_2)]:
        asic_instance = ingress_duthost.get_port_asic_instance(tx_port['peer_port'])
        fabric_mapping = get_fabric_mapping(ingress_duthost, asic_instance)
        ingress_fabric_mapping_dict.setdefault(ingress_duthost, {})[asic_instance] = fabric_mapping

    egress_asic_instance = egress_duthost.get_port_asic_instance(rx_port['peer_port'])
    egress_fabric_mapping = get_fabric_mapping(egress_duthost, egress_asic_instance)

    if is_bp_fabric_ecn_check_required:
        snappi_extra_params.multi_dut_params.ingress_duthosts.append(supervisor_dut)
        clear_bp_fabric_queue_counters(ingress_fabric_mapping_dict,
                                       egress_fabric_mapping, supervisor_dut, test_prio_list)

        for priority in test_prio_list:
            get_npu_voq_queue_counters(duthost, dut_port, priority, True)

    initial_counters = {priority: get_npu_voq_queue_counters(duthost, dut_port, priority)
                        for priority in test_prio_list}

    _generate_traffic_config(testbed_config, snappi_extra_params,
                             port_config_list, test_prio_list,
                             test_flow_percent, prio_dscp_map,
                             congested=True)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

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

    post_counters = {priority: get_npu_voq_queue_counters(duthost, dut_port, priority)
                     for priority in test_prio_list}
    ecn_counters = [(initial_counters[p], post_counters[p]) for p in test_prio_list]

    ecn_marking_verified_on_egress = verify_ecn_counters(ecn_counters, is_bp_fabric_ecn_check_required)
    if not ecn_marking_verified_on_egress:
        if not check_bp_fabric_ecn_marking(ingress_fabric_mapping_dict, egress_fabric_mapping,
                                           supervisor_dut, test_prio_list):
            # Log PFC frame counts
            for dut, tx_port in [(ingress_duthost_1, tx_port_1), (ingress_duthost_2, tx_port_2)]:
                for priority in test_prio_list:
                    pfc_count = get_pfc_frame_count(dut, tx_port['peer_port'], priority, True)
                    logging.info("PFC Tx frame count for DUT {}, Port {}, Priority {}: {}".format(
                        dut.hostname, tx_port['peer_port'], priority, pfc_count))

            pytest_assert(False, "No ECN marking in the data path")
