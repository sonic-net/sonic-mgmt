import logging
import time
import os
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts              # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     snappi_api                                                                                      # noqa: F401
from tests.common.snappi_tests.snappi_helpers import get_dut_port_id
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector, config_wred, \
    enable_ecn, config_ingress_lossless_buffer_alpha, stop_pfcwd, disable_packet_aging, \
    config_capture_pkt, traffic_flow_mode, calc_pfc_pause_flow_rate, packet_capture, clear_counters  # noqa: F401
from tests.common.snappi_tests.read_pcap import get_ipv4_pkts
from tests.common.snappi_tests.snappi_helpers import wait_for_arp, fetch_snappi_flow_metrics
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config, \
    generate_test_flows, generate_pause_flows, run_traffic                                           # noqa: F401

logger = logging.getLogger(__name__)

EXP_DURATION_SEC = 1
DATA_START_DELAY_SEC = 0.2
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
                 default_ecn,
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
    # snappi_extra_params.multi_dut_params.egress_duthosts = egress_duthost
    snappi_extra_params.multi_dut_params.egress_duthosts = [egress_duthost]

    tx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[1]
    ingress_duthost = tx_port['duthost']
    # snappi_extra_params.multi_dut_params.ingress_duthosts = ingress_duthost
    snappi_extra_params.multi_dut_params.ingress_duthosts = [ingress_duthost]

    pytest_assert(testbed_config is not None, 'Failed to get L2/3 testbed config')

    logger.info("Stopping PFC watchdog")
    stop_pfcwd(egress_duthost)
    stop_pfcwd(ingress_duthost)

    logger.info("Disabling packet aging if necessary")
    disable_packet_aging(egress_duthost, rx_port['asic_value'])
    disable_packet_aging(ingress_duthost, tx_port['asic_value'])

    # Configure WRED/ECN thresholds if not default test.
    if (not default_ecn):
        logger.info("Configuring WRED and ECN thresholds")
        config_result = config_wred(host_ans=ingress_duthost,
                                    kmin=snappi_extra_params.ecn_params["kmin"],
                                    kmax=snappi_extra_params.ecn_params["kmax"],
                                    pmax=snappi_extra_params.ecn_params["pmax"],
                                    kdrop=snappi_extra_params.ecn_params["pmax"],
                                    asic_value=tx_port['asic_value'])
        pytest_assert(config_result is True, 'Failed to configure WRED/ECN at the DUT')
        config_result = config_wred(host_ans=egress_duthost,
                                    kmin=snappi_extra_params.ecn_params["kmin"],
                                    kmax=snappi_extra_params.ecn_params["kmax"],
                                    pmax=snappi_extra_params.ecn_params["pmax"],
                                    kdrop=snappi_extra_params.ecn_params["pmax"],
                                    asic_value=rx_port['asic_value'])
        pytest_assert(config_result is True, 'Failed to configure WRED/ECN at the DUT')

    # Enable ECN marking
    logger.info("Enabling ECN markings")
    pytest_assert(enable_ecn(host_ans=egress_duthost, prio=lossless_prio, asic_value=rx_port['asic_value']),
                  'Unable to enable ecn')
    pytest_assert(enable_ecn(host_ans=ingress_duthost, prio=lossless_prio, asic_value=tx_port['asic_value']),
                  'Unable to enable ecn')

    # Get the ID of the port to test
    port_id = get_dut_port_id(dut_hostname=egress_duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    logger.info('Got the port_id:{} for device:{} and interface: {}'.format(port_id, egress_duthost.hostname, dut_port))

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
    snappi_extra_params.packet_capture_file = "ECN_cap"
    config_capture_pkt(testbed_config=testbed_config,
                       port_names=snappi_extra_params.packet_capture_ports,
                       capture_type=snappi_extra_params.packet_capture_type,
                       capture_name=snappi_extra_params.packet_capture_file)
    api.set_config(testbed_config)
    ixnetrestpy = api._ixnetwork
    ixnetrestpy.Traffic.EnableMinFrameSize = True
    cap_port = ixnetrestpy.Vport.find().Capture.find(HardwareEnabled=True)
    cap_port.SliceSize = 32

    logger.info("Running {} iteration(s)".format(iters))
    trafficItem = ixnetrestpy.Traffic.TrafficItem.find()
    trafficItem.Generate()
    ixnetrestpy.Traffic.Apply()

    logger.info("Running {} iteration(s)".format(iters))
    for i in range(iters):
        logger.info("Running iteration {}".format(i))
        logger.info("Packet capture file: {}.pcapng".format(snappi_extra_params.packet_capture_file))

        logger.info("Slicing Capture Disabled")
        cap_port.update(HardwareEnabled=False, SoftwareEnabled=False)
        time.sleep(1)

        logger.info("Slicing Capture Enabled")
        cap_port.update(HardwareEnabled=True, SoftwareEnabled=True)
        time.sleep(1)

        logger.info("Running traffic")
        run_ecn_traffic(duthost=egress_duthost,
                        api=api,
                        config=testbed_config,
                        data_flow_names=data_flow_names,
                        all_flow_names=all_flow_names,
                        exp_dur_sec=EXP_DURATION_SEC,
                        snappi_extra_params=snappi_extra_params,
                        is_ecn=True)

        result.append(get_ipv4_pkts(snappi_extra_params.packet_capture_file + ".pcapng", protocol_num=17))
        os.rename(snappi_extra_params.packet_capture_file + ".pcapng",
                  snappi_extra_params.packet_capture_file + "_{}.pcapng".format(i))
        time.sleep(2)

    return result


def run_ecn_traffic(duthost,
                    api,
                    config,
                    data_flow_names,
                    all_flow_names,
                    exp_dur_sec,
                    snappi_extra_params,
                    is_ecn=False):

    logger.info("Wait for Arp to Resolve ...")
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)
    pcap_type = snappi_extra_params.packet_capture_type
    # base_flow_config = snappi_extra_params.base_flow_config

    if pcap_type != packet_capture.NO_CAPTURE:
        logger.info("Starting packet capture ...")
        cs = api.control_state()
        cs.port.capture.port_names = snappi_extra_params.packet_capture_ports
        cs.port.capture.state = cs.port.capture.START
        api.set_control_state(cs)

    logger.info('Clearing DUT interfaces, queue and drop counters')
    device_list = []
    port_list = []
    for port in snappi_extra_params.multi_dut_params.multi_dut_ports:
        device_list.append(port['duthost'])
        port_list.append(port['peer_port'])
    for dut, port in zip(device_list, port_list):
        clear_counters(dut, port)

    logger.info("Starting transmit on all flows ...")
    # Enabling frame-size (slicing) to ensure captures are set for more than 16k packets.
    logger.info('Starting the ECN test with RestPY')
    logger.info('EnableMinFrameSize:{}'.format(api._ixnetwork.Traffic.EnableMinFrameSize))
    trafficItem1 = api._ixnetwork.Traffic.TrafficItem.find()
    trafficItem1.StartStatelessTrafficBlocking()

    time.sleep(60)

    if pcap_type != packet_capture.NO_CAPTURE:
        logger.info("Stopping packet capture ...")
        request = api.capture_request()
        request.port_name = snappi_extra_params.packet_capture_ports[0]
        cs = api.control_state()
        cs.port.capture.state = cs.port.capture.STOP
        api.set_control_state(cs)
        logger.info("Retrieving and saving packet capture to {}.pcapng".format(snappi_extra_params.packet_capture_file))
        pcap_bytes = api.get_capture(request)
        with open(snappi_extra_params.packet_capture_file + ".pcapng", 'wb') as fid:
            fid.write(pcap_bytes.getvalue())

    # Dump per-flow statistics
    logger.info("Dumping per-flow statistics")
    flow_metrics = fetch_snappi_flow_metrics(api, all_flow_names)
    logger.info("Stopping transmit on all remaining flows")
    # Using restPy to stop the traffic in case restPy is used to start it.
    trafficItem1 = api._ixnetwork.Traffic.TrafficItem.find()
    trafficItem1.StopStatelessTrafficBlocking()

    for row in flow_metrics:
        logger.info('for {}, loss:{}'.format(row.name, int(row.loss)))
        if 'Test Flow' in row.name:
            pytest_assert(int(row.loss) == 0, "{} must have NO loss".format(row.name))
