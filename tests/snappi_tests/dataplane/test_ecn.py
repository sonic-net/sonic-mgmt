from tests.snappi_tests.dataplane.imports import *

logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('tgen')]

EXP_DURATION_SEC = 2.1
DATA_START_DELAY_SEC = 1
PAUSE_FLOW_NAME = 'Pause Storm'
DATA_FLOW_NAME = 'Data Flow'


def run_ecn_test(api,
                 testbed_config,
                 port_config_list,
                 conn_data,
                 fanout_data,
                 duthost,
                 dut_port,
                 lossless_prio,
                 prio_dscp_map,
                 iters,
                 snappi_extra_params=None):
    """
    Run a ECN test

    Args:
        api (obj): SNAPPI session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        lossless_prio (int): lossless priority
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        iters (int): # of iterations in the test
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic

    Returns:
        Return captured IP packets (list of list)
    """

    pytest_assert(testbed_config is not None, 'Failed to get L2/3 testbed config')

    logger.info("Stopping PFC watchdog")
    stop_pfcwd(duthost)
    logger.info("Disabling packet aging if necessary")
    disable_packet_aging(duthost)

    # Configure WRED/ECN thresholds
    logger.info("Configuring WRED and ECN thresholds")
    config_result = config_wred(host_ans=duthost,
                                kmin=snappi_extra_params.ecn_params["kmin"],
                                kmax=snappi_extra_params.ecn_params["kmax"],
                                pmax=snappi_extra_params.ecn_params["pmax"])
    pytest_assert(config_result is True, 'Failed to configure WRED/ECN at the DUT')

    # Enable ECN marking
    logger.info("Enabling ECN markings")
    enable_ecn(host_ans=duthost, prio=lossless_prio)

    # Configure PFC threshold to 2 ^ 3
    config_result = config_ingress_lossless_buffer_alpha(host_ans=duthost,
                                                         alpha_log2=3)

    pytest_assert(config_result is True, 'Failed to configure PFC threshold to 8')

    logger.info("Waiting on ECN and dynamic buffer configuration to take effect. Sleeping for 10 seconds.")
    time.sleep(10)

    # Get the ID of the port to test
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Failed to get ID for port {}'.format(dut_port))

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])

    # Generate base traffic config
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
        run_traffic(duthost=duthost,
                    api=api,
                    config=testbed_config,
                    data_flow_names=data_flow_names,
                    all_flow_names=all_flow_names,
                    exp_dur_sec=EXP_DURATION_SEC,
                    snappi_extra_params=snappi_extra_params)

        result.append(get_ipv4_pkts(snappi_extra_params.packet_capture_file + ".pcapng"))

    return result

def test_red_accuracy(request,
                      snappi_api,                       # noqa F811
                      snappi_testbed_config,            # noqa F811
                      conn_graph_facts,                 # noqa F811
                      fanout_graph_facts,               # noqa F811
                      duthosts,
                      rand_one_dut_hostname,
                      rand_one_dut_portname_oper_up,
                      rand_one_dut_lossless_prio,
                      prio_dscp_map):                   # noqa F811
    """
    Measure RED/ECN marking accuracy of the device under test (DUT).
    Dump queue length vs. ECN marking probability results into a file.

    Args:
        request (pytest fixture): pytest request object
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
        rand_one_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """
    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    dut_hostname2, lossless_prio = rand_one_dut_lossless_prio.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname == dut_hostname2,
                   "Priority and port are not mapped to the expected DUT")

    pytest_require(rand_one_dut_hostname == dut_hostname,"Port is not mapped to the expected DUT")
    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]
    skip_ecn_tests(duthost)
    lossless_prio = int(lossless_prio)

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.packet_capture_type = packet_capture.IP_CAPTURE
    snappi_extra_params.is_snappi_ingress_port_cap = True
    snappi_extra_params.ecn_params = {'kmin': 500000, 'kmax': 900000, 'pmax': 5}
    data_flow_pkt_size = 1024
    data_flow_pkt_count = 910
    num_iterations = 1

    logger.info("Running ECN red accuracy test with ECN params: {}".format(snappi_extra_params.ecn_params))
    logger.info("Running ECN red accuracy test for {} iterations".format(num_iterations))

    snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_pkt_size": data_flow_pkt_size,
            "flow_pkt_count": data_flow_pkt_count
        }

    ip_pkts_list = run_ecn_test(api=snappi_api,
                                testbed_config=testbed_config,
                                port_config_list=port_config_list,
                                conn_data=conn_graph_facts,
                                fanout_data=fanout_graph_facts,
                                duthost=duthost,
                                dut_port=dut_port,
                                lossless_prio=lossless_prio,
                                prio_dscp_map=prio_dscp_map,
                                iters=num_iterations,
                                snappi_extra_params=snappi_extra_params)

    # Check if we capture packets of all the rounds """
    pytest_assert(len(ip_pkts_list) == num_iterations,
                  'Only capture {}/{} rounds of packets'.format(len(ip_pkts_list), num_iterations))


    import pdb;pdb.set_trace()
    for iter, ip_pkts in enumerate(ip_pkts_list):
        # Check if the first packet is ECN marked
        pytest_assert(is_ecn_marked(ip_pkts[0]), "Iteration{}: The first packet should be marked".format(iter+1))
        # Check if the last packet is not ECN marked
        pytest_assert(not is_ecn_marked(ip_pkts[-1]),"Iteration{}: The last packet should not be marked".format(iter+1))


    logger.info("Initializing queue length vs. ECN marking probability dictionary")

    # Initialize the queue_mark_cnt dictionary with queue lengths as keys and 0 as values
    queue_mark_cnt = collections.defaultdict(int)
    logger.info("Verifying that all packets are captured in each iteration")

    # Process captured packets for each iteration
    for iteration, captured_packets in enumerate(ip_pkts_list):
        # Ensure all packets are captured
        pytest_assert(
            len(captured_packets) == data_flow_pkt_count,
            f"Only captured {len(captured_packets)}/{data_flow_pkt_count} packets in round {iteration}"
        )
        import pdb;pdb.set_trace()
        # Update queue mark counts efficiently
        for packet_index, packet in enumerate(captured_packets):
            queue_length = (data_flow_pkt_count - packet_index) * data_flow_pkt_size
            queue_mark_cnt[queue_length] += is_ecn_marked(packet)

    # Dump queue length vs. ECN marking probability into logger file """
    logger.info("------- Dumping queue length vs. ECN marking probability data ------")
    # Calculate the ECN marking probability and sort by queue length
    output_table = [
        [queue, mark_cnt / num_iterations]
        for queue, mark_cnt in sorted(queue_mark_cnt.items())
    ]
    
    logger.info(tabulate(output_table, headers=['Queue Length', 'ECN Marking Probability']))

    # Teardown ECN config through a reload
    logger.info("Reloading config to teardown ECN config")
    config_reload(sonic_host=duthost, config_source='config_db', safe_reload=True)
