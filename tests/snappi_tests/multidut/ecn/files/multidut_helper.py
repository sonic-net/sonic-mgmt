import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts             # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     snappi_api                                                                                     # noqa: F401
from tests.common.snappi_tests.snappi_helpers import get_dut_port_id
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector, config_wred, \
    enable_ecn, config_ingress_lossless_buffer_alpha, stop_pfcwd, disable_packet_aging, \
    config_capture_pkt, traffic_flow_mode, calc_pfc_pause_flow_rate  # noqa: F401
from tests.common.snappi_tests.read_pcap import get_ip_pkts
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config, generate_test_flows, \
    generate_pause_flows, run_traffic                                       # noqa: F401

logger = logging.getLogger(__name__)

EXP_DURATION_SEC = 1
DATA_START_DELAY_SEC = 0.1
SNAPPI_POLL_DELAY_SEC = 2
PAUSE_FLOW_NAME = 'Pause Storm'
DATA_FLOW_NAME = 'Data Flow'


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

    duthost1 = snappi_extra_params.multi_dut_params.duthost1
    rx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[0]
    duthost2 = snappi_extra_params.multi_dut_params.duthost2
    tx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[1]
    iters = snappi_extra_params.test_iterations

    pytest_assert(testbed_config is not None, 'Failed to get L2/3 testbed config')

    logger.info("Stopping PFC watchdog")
    stop_pfcwd(duthost1, rx_port['asic_value'])
    stop_pfcwd(duthost2, tx_port['asic_value'])
    logger.info("Disabling packet aging if necessary")
    disable_packet_aging(duthost1)
    disable_packet_aging(duthost2)

    # Configure WRED/ECN thresholds
    logger.info("Configuring WRED and ECN thresholds")
    config_result = config_wred(host_ans=duthost1,
                                kmin=snappi_extra_params.ecn_params["kmin"],
                                kmax=snappi_extra_params.ecn_params["kmax"],
                                pmax=snappi_extra_params.ecn_params["pmax"])
    pytest_assert(config_result is True, 'Failed to configure WRED/ECN at the DUT')
    config_result = config_wred(host_ans=duthost2,
                                kmin=snappi_extra_params.ecn_params["kmin"],
                                kmax=snappi_extra_params.ecn_params["kmax"],
                                pmax=snappi_extra_params.ecn_params["pmax"])
    pytest_assert(config_result is True, 'Failed to configure WRED/ECN at the DUT')

    # Enable ECN marking
    logger.info("Enabling ECN markings")
    pytest_assert(enable_ecn(host_ans=duthost1, prio=lossless_prio), 'Unable to enable ecn')
    pytest_assert(enable_ecn(host_ans=duthost2, prio=lossless_prio), 'Unable to enable ecn')

    config_result = config_ingress_lossless_buffer_alpha(host_ans=duthost1,
                                                         alpha_log2=3)

    pytest_assert(config_result is True, 'Failed to configure PFC threshold to 8')
    config_result = config_ingress_lossless_buffer_alpha(host_ans=duthost2,
                                                         alpha_log2=3)

    pytest_assert(config_result is True, 'Failed to configure PFC threshold to 8')

    # Get the ID of the port to test
    port_id = get_dut_port_id(dut_hostname=duthost1.hostname,
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
        run_traffic(duthost=duthost1,
                    api=api,
                    config=testbed_config,
                    data_flow_names=data_flow_names,
                    all_flow_names=all_flow_names,
                    exp_dur_sec=EXP_DURATION_SEC,
                    snappi_extra_params=snappi_extra_params)

        result.append(get_ip_pkts(snappi_extra_params.packet_capture_file + ".pcapng"))

    return result
