"""
This module allows various snappi based tests to generate various traffic configurations.
"""
import time
import logging
import random
import re
from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.common_helpers import get_egress_queue_count, pfc_class_enable_vector, \
    get_lossless_buffer_size, get_pg_dropped_packets, \
    sec_to_nanosec, get_pfc_frame_count, packet_capture, get_tx_frame_count, get_rx_frame_count, \
    traffic_flow_mode
from tests.common.snappi_tests.port import select_ports, select_tx_port
from tests.common.snappi_tests.snappi_helpers import wait_for_arp, fetch_snappi_flow_metrics
from .variables import pfcQueueGroupSize, pfcQueueValueDict
from tests.common.cisco_data import is_cisco_device

logger = logging.getLogger(__name__)

SNAPPI_POLL_DELAY_SEC = 2
CONTINUOUS_MODE = -5
ANSIBLE_POLL_DELAY_SEC = 4


def setup_base_traffic_config(testbed_config,
                              port_config_list,
                              port_id):
    """
    Generate base configurations of flows, including test flows, background flows and
    pause storm. Test flows and background flows are also known as data flows.
    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test

    Returns:
        base_flow_config (dict): base flow configuration containing dut_port_config, tx_mac,
            rx_mac, tx_port_config, rx_port_config, tx_port_name, rx_port_name
            dict key-value pairs (all keys are strings):
                tx_port_id (int): ID of ixia TX port ex. 1
                rx_port_id (int): ID of ixia RX port ex. 2
                tx_port_config (SnappiPortConfig): port config obj for ixia TX port
                rx_port_config (SnappiPortConfig): port config obj for ixia RX port
                tx_mac (str): MAC address of ixia TX port ex. '00:00:fa:ce:fa:ce'
                rx_mac (str): MAC address of ixia RX port ex. '00:00:fa:ce:fa:ce'
                tx_port_name (str): name of ixia TX port ex. 'Port 1'
                rx_port_name (str): name of ixia RX port ex. 'Port 2'
                dut_port_config (list): a list of two dictionaries of tx and rx ports on the peer (switch) side,
                                        and the associated test priorities
                                        ex. [{'Ethernet4':[3, 4]}, {'Ethernet8':[3, 4]}]
                test_flow_name_dut_rx_port_map (dict): Mapping of test flow name to DUT RX port(s)
                                                  ex. {'flow1': [Ethernet4, Ethernet8]}
                test_flow_name_dut_tx_port_map (dict): Mapping of test flow name to DUT TX port(s)
                                                  ex. {'flow1': [Ethernet4, Ethernet8]}
    """
    base_flow_config = {}
    rx_port_id = port_id
    tx_port_id_list, _ = select_ports(port_config_list=port_config_list,
                                      pattern="many to one",
                                      rx_port_id=rx_port_id)

    pytest_assert(len(tx_port_id_list) > 0, "Cannot find any TX ports")
    tx_port_id = select_tx_port(tx_port_id_list=tx_port_id_list,
                                rx_port_id=rx_port_id)
    pytest_assert(tx_port_id is not None, "Cannot find a suitable TX port")
    base_flow_config["rx_port_id"] = rx_port_id
    base_flow_config["tx_port_id"] = tx_port_id

    tx_port_config = next((x for x in port_config_list if x.id == tx_port_id), None)
    rx_port_config = next((x for x in port_config_list if x.id == rx_port_id), None)
    base_flow_config["tx_port_config"] = tx_port_config
    base_flow_config["rx_port_config"] = rx_port_config

    # Instantiate peer ports in dut_port_config
    dut_port_config = []
    tx_dict = {str(tx_port_config.peer_port): []}
    rx_dict = {str(rx_port_config.peer_port): []}
    dut_port_config.append(tx_dict)
    dut_port_config.append(rx_dict)
    base_flow_config["dut_port_config"] = dut_port_config

    base_flow_config["tx_mac"] = tx_port_config.mac
    if tx_port_config.gateway == rx_port_config.gateway and \
       tx_port_config.prefix_len == rx_port_config.prefix_len:
        """ If soruce and destination port are in the same subnet """
        base_flow_config["rx_mac"] = rx_port_config.mac
    else:
        base_flow_config["rx_mac"] = tx_port_config.gateway_mac

    base_flow_config["tx_port_name"] = testbed_config.ports[tx_port_id].name
    base_flow_config["rx_port_name"] = testbed_config.ports[rx_port_id].name

    return base_flow_config


def generate_test_flows(testbed_config,
                        test_flow_prio_list,
                        prio_dscp_map,
                        snappi_extra_params,
                        number_of_streams=1):
    """
    Generate configurations of test flows. Test flows and background flows are also known as data flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        test_flow_prio_list (list): list of test flow priorities
        prio_dscp_map (dict): priority to DSCP mapping
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        number_of_streams (int): number of UDP streams
    """
    base_flow_config = snappi_extra_params.base_flow_config
    pytest_assert(base_flow_config is not None, "Cannot find base flow configuration")
    data_flow_config = snappi_extra_params.traffic_flow_config.data_flow_config
    pytest_assert(data_flow_config is not None, "Cannot find data flow configuration")
    test_flow_name_dut_rx_port_map = {}
    test_flow_name_dut_tx_port_map = {}

    # Check if flow_rate_percent is a dictionary
    if isinstance(data_flow_config["flow_rate_percent"], (int, float)):
        # Create a dictionary with priorities as keys and the flow rate percent as the value for each key
        data_flow_config["flow_rate_percent"] = {
            prio: data_flow_config["flow_rate_percent"] for prio in test_flow_prio_list
        }

    for prio in test_flow_prio_list:
        test_flow_name = "{} Prio {}".format(data_flow_config["flow_name"], prio)
        test_flow = testbed_config.flows.flow(name=test_flow_name)[-1]
        test_flow.tx_rx.port.tx_name = base_flow_config["tx_port_name"]
        test_flow.tx_rx.port.rx_name = base_flow_config["rx_port_name"]

        eth, ipv4, udp = test_flow.packet.ethernet().ipv4().udp()
        src_port = random.randint(5000, 6000)
        udp.src_port.increment.start = src_port
        udp.src_port.increment.step = 1
        udp.src_port.increment.count = number_of_streams

        eth.src.value = base_flow_config["tx_mac"]
        eth.dst.value = base_flow_config["rx_mac"]
        if pfcQueueGroupSize == 8:
            eth.pfc_queue.value = prio
        else:
            eth.pfc_queue.value = pfcQueueValueDict[prio]

        ipv4.src.value = base_flow_config["tx_port_config"].ip
        ipv4.dst.value = base_flow_config["rx_port_config"].ip
        ipv4.priority.choice = ipv4.priority.DSCP
        ipv4.priority.dscp.phb.values = prio_dscp_map[prio]
        ipv4.priority.dscp.ecn.value = (
            ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

        test_flow.size.fixed = data_flow_config["flow_pkt_size"]
        test_flow.rate.percentage = data_flow_config["flow_rate_percent"][prio]
        if data_flow_config["flow_traffic_type"] == traffic_flow_mode.FIXED_DURATION:
            test_flow.duration.fixed_seconds.seconds = data_flow_config["flow_dur_sec"]
            test_flow.duration.fixed_seconds.delay.nanoseconds = int(sec_to_nanosec
                                                                     (data_flow_config["flow_delay_sec"]))
        elif data_flow_config["flow_traffic_type"] == traffic_flow_mode.FIXED_PACKETS:
            test_flow.duration.fixed_packets.packets = data_flow_config["flow_pkt_count"]
            test_flow.duration.fixed_packets.delay.nanoseconds = int(sec_to_nanosec
                                                                     (data_flow_config["flow_delay_sec"]))

        test_flow.metrics.enable = True
        test_flow.metrics.loss = True

        """ Set flow port config values """
        dut_port_config = base_flow_config["dut_port_config"]
        dut_port_config[0][str(base_flow_config["tx_port_config"].peer_port)].append(int(prio))
        dut_port_config[1][str(base_flow_config["rx_port_config"].peer_port)].append(int(prio))
        base_flow_config["dut_port_config"] = dut_port_config

        # Save flow name to TX and RX port mapping for DUT
        test_flow_name_dut_rx_port_map[test_flow_name] = [base_flow_config["tx_port_config"].peer_port]
        test_flow_name_dut_tx_port_map[test_flow_name] = [base_flow_config["rx_port_config"].peer_port]

    base_flow_config["test_flow_name_dut_rx_port_map"] = test_flow_name_dut_rx_port_map
    base_flow_config["test_flow_name_dut_tx_port_map"] = test_flow_name_dut_tx_port_map

    snappi_extra_params.base_flow_config = base_flow_config


def generate_background_flows(testbed_config,
                              bg_flow_prio_list,
                              prio_dscp_map,
                              snappi_extra_params):
    """
    Generate background configurations of flows. Test flows and background flows are also known as data flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        bg_flow_prio_list (list): list of background flow priorities
        prio_dscp_map (dict): priority to DSCP mapping
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """
    base_flow_config = snappi_extra_params.base_flow_config
    pytest_assert(base_flow_config is not None, "Cannot find base flow configuration")
    bg_flow_config = snappi_extra_params.traffic_flow_config.background_flow_config
    pytest_assert(bg_flow_config is not None, "Cannot find background flow configuration")

    for prio in bg_flow_prio_list:
        bg_flow = testbed_config.flows.flow(name='{} Prio {}'.format(bg_flow_config["flow_name"], prio))[-1]
        bg_flow.tx_rx.port.tx_name = base_flow_config["tx_port_name"]
        bg_flow.tx_rx.port.rx_name = base_flow_config["rx_port_name"]

        eth, ipv4 = bg_flow.packet.ethernet().ipv4()
        eth.src.value = base_flow_config["tx_mac"]
        eth.dst.value = base_flow_config["rx_mac"]
        if pfcQueueGroupSize == 8:
            eth.pfc_queue.value = prio
        else:
            eth.pfc_queue.value = pfcQueueValueDict[prio]

        ipv4.src.value = base_flow_config["tx_port_config"].ip
        ipv4.dst.value = base_flow_config["rx_port_config"].ip
        ipv4.priority.choice = ipv4.priority.DSCP
        ipv4.priority.dscp.phb.values = prio_dscp_map[prio]
        ipv4.priority.dscp.ecn.value = (
            ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

        bg_flow.size.fixed = bg_flow_config["flow_pkt_size"]
        bg_flow.rate.percentage = bg_flow_config["flow_rate_percent"]
        bg_flow.duration.fixed_seconds.seconds = bg_flow_config["flow_dur_sec"]
        bg_flow.duration.fixed_seconds.delay.nanoseconds = int(sec_to_nanosec
                                                               (bg_flow_config["flow_delay_sec"]))

        bg_flow.metrics.enable = True
        bg_flow.metrics.loss = True


def generate_pause_flows(testbed_config,
                         pause_prio_list,
                         global_pause,
                         snappi_extra_params):
    """
    Generate configurations of pause flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        pause_prio_list (list): list of pause priorities
        global_pause (bool): global pause or per priority pause
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """
    base_flow_config = snappi_extra_params.base_flow_config
    pytest_assert(base_flow_config is not None, "Cannot find base flow configuration")
    pause_flow_config = snappi_extra_params.traffic_flow_config.pause_flow_config
    pytest_assert(pause_flow_config is not None, "Cannot find pause flow configuration")

    pause_flow = testbed_config.flows.flow(name=pause_flow_config["flow_name"])[-1]
    pause_flow.tx_rx.port.tx_name = testbed_config.ports[base_flow_config["rx_port_id"]].name
    pause_flow.tx_rx.port.rx_name = testbed_config.ports[base_flow_config["tx_port_id"]].name

    if global_pause:
        pause_pkt = pause_flow.packet.ethernetpause()[-1]
        pause_pkt.dst.value = "01:80:C2:00:00:01"
        pause_pkt.src.value = snappi_extra_params.pfc_pause_src_mac if snappi_extra_params.pfc_pause_src_mac \
            else "00:00:fa:ce:fa:ce"
    else:
        pause_time = []
        for x in range(8):
            if x in pause_prio_list:
                pause_time.append(int('ffff', 16))
            else:
                pause_time.append(int('0000', 16))

        vector = pfc_class_enable_vector(pause_prio_list)
        pause_pkt = pause_flow.packet.pfcpause()[-1]
        pause_pkt.src.value = snappi_extra_params.pfc_pause_src_mac if snappi_extra_params.pfc_pause_src_mac \
            else "00:00:fa:ce:fa:ce"
        pause_pkt.dst.value = "01:80:C2:00:00:01"
        pause_pkt.class_enable_vector.value = vector if snappi_extra_params.set_pfc_class_enable_vec else 0
        pause_pkt.pause_class_0.value = pause_time[0]
        pause_pkt.pause_class_1.value = pause_time[1]
        pause_pkt.pause_class_2.value = pause_time[2]
        pause_pkt.pause_class_3.value = pause_time[3]
        pause_pkt.pause_class_4.value = pause_time[4]
        pause_pkt.pause_class_5.value = pause_time[5]
        pause_pkt.pause_class_6.value = pause_time[6]
        pause_pkt.pause_class_7.value = pause_time[7]

    # Pause frames are sent from the RX port of ixia
    pause_flow.rate.pps = pause_flow_config["flow_rate_pps"]
    pause_flow.size.fixed = pause_flow_config["flow_pkt_size"]
    pause_flow.duration.fixed_seconds.delay.nanoseconds = int(sec_to_nanosec(
        pause_flow_config["flow_delay_sec"]))

    if pause_flow_config["flow_traffic_type"] == traffic_flow_mode.FIXED_DURATION:
        pause_flow.duration.fixed_seconds.seconds = pause_flow_config["flow_dur_sec"]
    elif pause_flow_config["flow_traffic_type"] == traffic_flow_mode.CONTINUOUS:
        pause_flow.duration.choice = pause_flow.duration.CONTINUOUS

    pause_flow.metrics.enable = True
    pause_flow.metrics.loss = True


def clear_dut_interface_counters(duthost):
    """
    Clears the dut interface counter.
    Args:
        duthost (obj): DUT host object
    """
    duthost.command("sonic-clear counters \n")


def clear_dut_que_counters(duthost):
    """
    Clears the dut que counter.
    Args:
        duthost (obj): DUT host object
    """
    duthost.command("sonic-clear queuecounters \n")


def run_traffic(duthost,
                api,
                config,
                data_flow_names,
                all_flow_names,
                exp_dur_sec,
                snappi_extra_params):

    """
    Run traffic and return per-flow statistics, and capture packets if needed.
    Args:
        duthost (obj): DUT host object
        api (obj): snappi session
        config (obj): experiment config (testbed config + flow config)
        data_flow_names (list): list of names of data (test and background) flows
        all_flow_names (list): list of names of all the flows
        exp_dur_sec (int): experiment duration in second
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
        flow_metrics (snappi metrics object): per-flow statistics from TGEN (right after flows end)
        switch_device_results (dict): statistics from DUT on both TX and RX and per priority
        in_flight_flow_metrics (snappi metrics object): in-flight statistics per flow from TGEN
                                                        (right before flows end)
    """

    api.set_config(config)
    logger.info("Wait for Arp to Resolve ...")
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)
    pcap_type = snappi_extra_params.packet_capture_type
    base_flow_config = snappi_extra_params.base_flow_config
    switch_tx_lossless_prios = sum(base_flow_config["dut_port_config"][1].values(), [])
    switch_rx_port = snappi_extra_params.base_flow_config["tx_port_config"].peer_port
    switch_tx_port = snappi_extra_params.base_flow_config["rx_port_config"].peer_port
    switch_device_results = None
    in_flight_flow_metrics = None

    if pcap_type != packet_capture.NO_CAPTURE:
        logger.info("Starting packet capture ...")
        cs = api.capture_state()
        cs.port_names = snappi_extra_params.packet_capture_ports
        cs.state = cs.START
        api.set_capture_state(cs)

    for host in set([*snappi_extra_params.multi_dut_params.ingress_duthosts,
                     *snappi_extra_params.multi_dut_params.egress_duthosts, duthost]):
        clear_dut_interface_counters(host)
        clear_dut_que_counters(host)

    logger.info("Starting transmit on all flows ...")
    ts = api.transmit_state()
    ts.state = ts.START
    api.set_transmit_state(ts)

    # Test needs to run for at least 10 seconds to allow successive device polling
    if snappi_extra_params.poll_device_runtime and exp_dur_sec > 10:
        logger.info("Polling DUT for traffic statistics for {} seconds ...".format(exp_dur_sec))
        switch_device_results = {}
        switch_device_results["tx_frames"] = {}
        switch_device_results["rx_frames"] = {}
        for lossless_prio in switch_tx_lossless_prios:
            switch_device_results["tx_frames"][lossless_prio] = []
            switch_device_results["rx_frames"][lossless_prio] = []
        exp_dur_sec = exp_dur_sec + ANSIBLE_POLL_DELAY_SEC  # extra time to allow for device polling
        poll_freq_sec = int(exp_dur_sec / 10)

        for poll_iter in range(10):
            for lossless_prio in switch_tx_lossless_prios:
                switch_device_results["tx_frames"][lossless_prio].append(get_egress_queue_count(duthost, switch_tx_port,
                                                                                                lossless_prio)[0])
                switch_device_results["rx_frames"][lossless_prio].append(get_egress_queue_count(duthost, switch_rx_port,
                                                                                                lossless_prio)[0])
            time.sleep(poll_freq_sec)

            if poll_iter == 5:
                logger.info("Polling TGEN for in-flight traffic statistics...")
                in_flight_flow_metrics = fetch_snappi_flow_metrics(api, all_flow_names)
                flow_names = [metric.name for metric in in_flight_flow_metrics if metric.name in data_flow_names]
                tx_frames = [metric.frames_tx for metric in in_flight_flow_metrics if metric.name in data_flow_names]
                rx_frames = [metric.frames_rx for metric in in_flight_flow_metrics if metric.name in data_flow_names]
                logger.info("In-flight traffic statistics for flows: {}".format(flow_names))
                logger.info("In-flight TX frames: {}".format(tx_frames))
                logger.info("In-flight RX frames: {}".format(rx_frames))
        logger.info("DUT polling complete")
    else:
        time.sleep(exp_dur_sec*(2/5))  # no switch polling required, only TGEN polling
        logger.info("Polling TGEN for in-flight traffic statistics...")
        in_flight_flow_metrics = fetch_snappi_flow_metrics(api, all_flow_names)  # fetch in-flight metrics from TGEN
        time.sleep(exp_dur_sec*(3/5))

    attempts = 0
    max_attempts = 20

    while attempts < max_attempts:
        logger.info("Checking if all flows have stopped. Attempt #{}".format(attempts + 1))
        flow_metrics = fetch_snappi_flow_metrics(api, data_flow_names)

        # If all the data flows have stopped
        transmit_states = [metric.transmit for metric in flow_metrics]
        if len(flow_metrics) == len(data_flow_names) and\
           list(set(transmit_states)) == ['stopped']:
            logger.info("All test and background traffic flows stopped")
            time.sleep(SNAPPI_POLL_DELAY_SEC)
            break
        else:
            time.sleep(1)
            attempts += 1

    pytest_assert(attempts < max_attempts,
                  "Flows do not stop in {} seconds".format(max_attempts))

    if pcap_type != packet_capture.NO_CAPTURE:
        logger.info("Stopping packet capture ...")
        request = api.capture_request()
        request.port_name = snappi_extra_params.packet_capture_ports[0]
        cs = api.capture_state()
        cs.state = cs.STOP
        api.set_capture_state(cs)
        logger.info("Retrieving and saving packet capture to {}.pcapng".format(snappi_extra_params.packet_capture_file))
        pcap_bytes = api.get_capture(request)
        with open(snappi_extra_params.packet_capture_file + ".pcapng", 'wb') as fid:
            fid.write(pcap_bytes.getvalue())

    # Dump per-flow statistics
    logger.info("Dumping per-flow statistics")
    flow_metrics = fetch_snappi_flow_metrics(api, all_flow_names)
    logger.info("Stopping transmit on all remaining flows")
    ts = api.transmit_state()
    ts.state = ts.STOP
    api.set_transmit_state(ts)

    return flow_metrics, switch_device_results, in_flight_flow_metrics


def verify_pause_flow(flow_metrics,
                      pause_flow_name):
    """
    Verify pause flow statistics i.e. all pause frames should be dropped

    Args:
        flow_metrics (list): per-flow statistics
        pause_flow_name (str): name of the pause flow
    Returns:
    """
    pause_flow_row = next(metric for metric in flow_metrics if metric.name == pause_flow_name)
    pause_flow_tx_frames = pause_flow_row.frames_tx
    pause_flow_rx_frames = pause_flow_row.frames_rx

    pytest_assert(pause_flow_tx_frames > 0 and pause_flow_rx_frames == 0,
                  "All the pause frames should be dropped")


def verify_background_flow(flow_metrics,
                           speed_gbps,
                           tolerance,
                           snappi_extra_params):
    """
    Verify background flow statistics. Background traffic on lossy priorities should not be dropped when there is no
    congestion, else some packets should be dropped if there is congestion.

    Args:
        flow_metrics (list): per-flow statistics
        speed_gbps (int): speed of the port in Gbps
        tolerance (float): tolerance for background flow deviation
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    bg_flow_config = snappi_extra_params.traffic_flow_config.background_flow_config

    for metric in flow_metrics:
        if bg_flow_config["flow_name"] not in metric.name:
            continue

        tx_frames = metric.frames_tx
        rx_frames = metric.frames_rx

        exp_bg_flow_rx_pkts = bg_flow_config["flow_rate_percent"] / 100.0 * speed_gbps \
            * 1e9 * bg_flow_config["flow_dur_sec"] / 8.0 / bg_flow_config["flow_pkt_size"]
        deviation = (rx_frames - exp_bg_flow_rx_pkts) / float(exp_bg_flow_rx_pkts)

        pytest_assert(tx_frames == rx_frames,
                      "{} should not have any dropped packet".format(metric.name))

        pytest_assert(abs(deviation) < tolerance,
                      "{} should receive {} packets (actual {})".format(metric.name, exp_bg_flow_rx_pkts, rx_frames))


def verify_basic_test_flow(flow_metrics,
                           speed_gbps,
                           tolerance,
                           test_flow_pause,
                           snappi_extra_params):
    """
    Verify basic test flow statistics from ixia. Test traffic on lossless priorities should not be dropped regardless
    of whether there is congestion or not.

    Args:
        flow_metrics (list): per-flow statistics
        speed_gbps (int): speed of the port in Gbps
        tolerance (float): tolerance for test flow deviation
        test_flow_pause (bool): whether test flow is expected to be paused
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    test_tx_frames = []
    data_flow_config = snappi_extra_params.traffic_flow_config.data_flow_config

    for metric in flow_metrics:
        if data_flow_config["flow_name"] not in metric.name:
            continue

        tx_frames = metric.frames_tx
        rx_frames = metric.frames_rx
        test_tx_frames.append(tx_frames)

        if test_flow_pause:
            pytest_assert(tx_frames > 0 and rx_frames == 0,
                          "{} should be paused".format(metric.name))
        else:
            pytest_assert(tx_frames == rx_frames,
                          "{} should not have any dropped packet".format(metric.name))

            # Check if flow_rate_percent is a dictionary
            if isinstance(data_flow_config["flow_rate_percent"], dict):
                # Extract the priority number from metric.name
                match = re.search(r'Prio (\d+)', metric.name)
                prio = int(match.group(1)) if match else None
                flow_rate_percent = data_flow_config["flow_rate_percent"].get(prio, 0)
            else:
                # Use the flow rate percent as is
                flow_rate_percent = data_flow_config["flow_rate_percent"]

            exp_test_flow_rx_pkts = flow_rate_percent / 100.0 * speed_gbps \
                * 1e9 * data_flow_config["flow_dur_sec"] / 8.0 / data_flow_config["flow_pkt_size"]

            deviation = (rx_frames - exp_test_flow_rx_pkts) / float(exp_test_flow_rx_pkts)
            pytest_assert(abs(deviation) < tolerance,
                          "{} should receive {} packets (actual {})".
                          format(data_flow_config["flow_name"], exp_test_flow_rx_pkts, rx_frames))

    snappi_extra_params.test_tx_frames = test_tx_frames


def verify_in_flight_buffer_pkts(duthost,
                                 flow_metrics,
                                 snappi_extra_params, asic_value=None):
    """
    Verify in-flight TX bytes of test flows should be held by switch buffer unless PFC delay is applied
    for when test traffic is expected to be paused

    Args:
        duthost (obj): DUT host object
        flow_metrics (list): per-flow statistics
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    data_flow_config = snappi_extra_params.traffic_flow_config.data_flow_config
    tx_frames_total = sum(metric.frames_tx for metric in flow_metrics if data_flow_config["flow_name"] in metric.name)
    tx_bytes_total = tx_frames_total * data_flow_config["flow_pkt_size"]
    dut_buffer_size = get_lossless_buffer_size(host_ans=duthost)
    headroom_test_params = snappi_extra_params.headroom_test_params
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, "Flow port config is not provided")

    if headroom_test_params is None:
        exceeds_headroom = False
    elif headroom_test_params[1]:
        exceeds_headroom = False
    else:
        exceeds_headroom = True

    if exceeds_headroom:
        pytest_assert(tx_bytes_total > dut_buffer_size,
                      "Total TX bytes {} should exceed DUT buffer size {}".
                      format(tx_bytes_total, dut_buffer_size))

        for peer_port, prios in dut_port_config[0].items():
            for prio in prios:
                dropped_packets = get_pg_dropped_packets(duthost, peer_port, prio, asic_value)
                pytest_assert(dropped_packets > 0,
                              "Total TX dropped packets {} should be more than 0".
                              format(dropped_packets))
    else:
        pytest_assert(tx_bytes_total < dut_buffer_size,
                      "Total TX bytes {} should be smaller than DUT buffer size {}".
                      format(tx_bytes_total, dut_buffer_size))

        for peer_port, prios in dut_port_config[0].items():
            for prio in prios:
                dropped_packets = get_pg_dropped_packets(duthost, peer_port, prio, asic_value)
                pytest_assert(dropped_packets == 0,
                              "Total TX dropped packets {} should be 0".
                              format(dropped_packets))


def verify_pause_frame_count_dut(rx_dut,
                                 tx_dut,
                                 test_traffic_pause,
                                 global_pause,
                                 snappi_extra_params):
    """
    Verify correct frame count for pause frames when the traffic is expected to be paused or not
    on the DUT

    Args:
        rx_dut (obj): Ingress DUT host object receiving packets from IXIA transmitter.
        tx_dut (obj): Egress DUT host object sending packets to IXIA, hence also receiving PFCs from IXIA.
        test_traffic_pause (bool): whether test traffic is expected to be paused
        global_pause (bool): if pause frame is IEEE 802.3X pause i.e. global pause applied
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')

    for peer_port, prios in dut_port_config[1].items():  # PFC pause frames received on DUT's egress port
        for prio in prios:
            pfc_pause_rx_frames = get_pfc_frame_count(tx_dut, peer_port, prio, is_tx=False)
            # For now, all PFC pause test cases send out PFC pause frames from the TGEN RX port to the DUT TX port,
            # except the case with global pause frames which SONiC does not count currently
            if global_pause:
                pytest_assert(pfc_pause_rx_frames == 0,
                              "Global pause frames should not be counted in RX PFC counters for priority {}"
                              .format(prio))
            elif not snappi_extra_params.set_pfc_class_enable_vec:
                pytest_assert(pfc_pause_rx_frames == 0,
                              "PFC pause frames with no bit set in the class enable vector should be dropped")
            else:
                if len(prios) > 1 and is_cisco_device(tx_dut) and not test_traffic_pause:
                    pytest_assert(pfc_pause_rx_frames == 0,
                                  "PFC pause frames should not be counted in RX PFC counters for priority {}"
                                  .format(prios))
                else:
                    pytest_assert(pfc_pause_rx_frames > 0,
                                  "PFC pause frames should be received and counted in RX PFC counters for priority {}"
                                  .format(prio))

    for peer_port, prios in dut_port_config[0].items():  # PFC pause frames sent by DUT's ingress port to TGEN
        for prio in prios:
            pfc_pause_tx_frames = get_pfc_frame_count(rx_dut, peer_port, prio, is_tx=True)
            if test_traffic_pause:
                pytest_assert(pfc_pause_tx_frames > 0,
                              "PFC pause frames should be transmitted and counted in TX PFC counters for priority {}"
                              .format(prio))
            else:
                # PFC pause frames should not be transmitted when test traffic is not paused
                pytest_assert(pfc_pause_tx_frames == 0,
                              "PFC pause frames should not be transmitted and counted in TX PFC counters")


def verify_tx_frame_count_dut(duthost,
                              api,
                              snappi_extra_params,
                              tx_frame_count_deviation=0.05,
                              tx_drop_frame_count_tol=5):
    """
    Verify correct frame count for tx frames on the DUT
    (OK and DROPS) when the traffic is expected to be paused on the DUT.
    DUT is polled after it stops receiving PFC pause frames from TGEN.
    Args:
        duthost (obj): DUT host object
        api (obj): snappi session
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        tx_frame_count_deviation (float): deviation for tx frame count (default to 1%)
        tx_drop_frame_count_tol (int): tolerance for tx drop frame count
    Returns:

    """
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')
    test_flow_name_dut_tx_port_map = snappi_extra_params.base_flow_config["test_flow_name_dut_tx_port_map"]

    # RX frames on DUT must TX once DUT stops receiving PFC pause frames
    for peer_port, _ in dut_port_config[1].items():
        # Collect metrics from TGEN once all flows have stopped
        test_flow_name = next((test_flow_name for test_flow_name, dut_tx_ports in test_flow_name_dut_tx_port_map.items()
                               if peer_port in dut_tx_ports), None)
        tgen_test_flow_metrics = fetch_snappi_flow_metrics(api, [test_flow_name])
        pytest_assert(tgen_test_flow_metrics, "TGEN test flow metrics is not provided")
        tgen_tx_frames = tgen_test_flow_metrics[0].frames_tx

        # Collect metrics from DUT once all flows have stopped
        tx_dut_frames, tx_dut_drop_frames = get_tx_frame_count(duthost, peer_port)

        # Verify metrics between TGEN and DUT
        pytest_assert(abs(tgen_tx_frames - tx_dut_frames)/tgen_tx_frames <= tx_frame_count_deviation,
                      "Additional frames are transmitted outside of deviation. Possible PFC frames are counted.")
        pytest_assert(tx_dut_drop_frames <= tx_drop_frame_count_tol, "No frames should be dropped")


def verify_rx_frame_count_dut(duthost,
                              api,
                              snappi_extra_params,
                              rx_frame_count_deviation=0.05,
                              rx_drop_frame_count_tol=5):
    """
    Verify correct frame count for rx frames on the DUT
    (OK and DROPS) when the traffic is expected to be paused on the DUT.
    Args:
        duthost (obj): DUT host object
        api (obj): snappi session
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        rx_frame_count_deviation (float): deviation for rx frame count (default to 1%)
        rx_drop_frame_count_tol (int): tolerance for tx drop frame count
    Returns:

    """
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')
    test_flow_name_dut_rx_port_map = snappi_extra_params.base_flow_config["test_flow_name_dut_rx_port_map"]

    # TX on TGEN is RX on DUT
    for peer_port, _ in dut_port_config[0].items():
        # Collect metrics from TGEN once all flows have stopped
        test_flow_name = next((test_flow_name for test_flow_name, dut_rx_ports in test_flow_name_dut_rx_port_map.items()
                               if peer_port in dut_rx_ports), None)
        tgen_test_flow_metrics = fetch_snappi_flow_metrics(api, [test_flow_name])
        pytest_assert(tgen_test_flow_metrics, "TGEN test flow metrics is not provided")
        tgen_rx_frames = tgen_test_flow_metrics[0].frames_rx

        # Collect metrics from DUT once all flows have stopped
        rx_frames, rx_drop_frames = get_rx_frame_count(duthost, peer_port)

        # Verify metrics between TGEN and DUT
        pytest_assert(abs(tgen_rx_frames - rx_frames)/tgen_rx_frames <= rx_frame_count_deviation,
                      "Additional frames are received outside of deviation. Possible PFC frames are counted.")
        pytest_assert(rx_drop_frames <= rx_drop_frame_count_tol, "No frames should be dropped")


def verify_unset_cev_pause_frame_count(duthost,
                                       snappi_extra_params):
    """
    Verify zero pause frames are counted when the PFC class enable vector is not set

    Args:
        duthost (obj): DUT host object
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')
    set_class_enable_vec = snappi_extra_params.set_pfc_class_enable_vec

    if not set_class_enable_vec:
        for peer_port, prios in dut_port_config[1].items():
            for prio in prios:
                pfc_pause_rx_frames = get_pfc_frame_count(duthost, peer_port, prio)
                pytest_assert(pfc_pause_rx_frames == 0,
                              "PFC pause frames with no bit set in the class enable vector should be dropped")


def verify_egress_queue_frame_count(duthost,
                                    switch_flow_stats,
                                    test_traffic_pause,
                                    snappi_extra_params,
                                    egress_queue_frame_count_tol=10):
    """
    Verify correct frame count for regular traffic from DUT egress queue

    Args:
        duthost (obj): DUT host object
        switch_flow_stats (dict): switch flow statistics
        test_traffic_pause (bool): whether test traffic is expected to be paused
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        egress_queue_frame_count_tol (int): tolerance for egress queue frame count when traffic is expected
                                            to be paused
    Returns:

    """
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')
    set_class_enable_vec = snappi_extra_params.set_pfc_class_enable_vec
    test_tx_frames = snappi_extra_params.test_tx_frames

    if test_traffic_pause:
        pytest_assert(switch_flow_stats, "Switch flow statistics is not provided")
        for prio, poll_data in switch_flow_stats["tx_frames"].items():
            mid_poll_index = int(len(poll_data)/2)
            next_poll_index = mid_poll_index + 1
            mid_poll_egress_queue_count = switch_flow_stats["tx_frames"][prio][mid_poll_index]
            next_poll_egress_queue_count = switch_flow_stats["tx_frames"][prio][next_poll_index]
            pytest_assert(next_poll_egress_queue_count - mid_poll_egress_queue_count <= egress_queue_frame_count_tol,
                          "Egress queue frame count should not increase when test traffic is paused")

    if not set_class_enable_vec and not test_traffic_pause:
        for peer_port, prios in dut_port_config[1].items():
            for prio in range(len(prios)):
                total_egress_packets, _ = get_egress_queue_count(duthost, peer_port, prios[prio])
                pytest_assert(total_egress_packets == test_tx_frames[prio],
                              "Queue counters should increment for invalid PFC pause frames")
