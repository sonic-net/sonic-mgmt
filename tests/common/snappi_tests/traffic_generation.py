"""
This module allows various snappi based tests to generate various traffic configurations.
"""

import time
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.common_helpers import get_egress_queue_count, pfc_class_enable_vector,\
    get_lossless_buffer_size, get_pg_dropped_packets,\
    sec_to_nanosec, get_pfc_frame_count, packet_capture
from tests.common.snappi_tests.port import select_ports, select_tx_port
from tests.common.snappi_tests.snappi_helpers import wait_for_arp

logger = logging.getLogger(__name__)

SNAPPI_POLL_DELAY_SEC = 2


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
                        test_flow_name,
                        test_flow_prio_list,
                        test_flow_rate_percent,
                        test_flow_dur_sec,
                        test_flow_delay_sec,
                        test_flow_pkt_size,
                        prio_dscp_map,
                        snappi_extra_params):
    """
    Generate configurations of test flows. Test flows and background flows are also known as data flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        test_flow_name (str): name of test flow
        test_flow_prio_list (list): list of test flow priorities
        test_flow_rate_percent (int): rate percentage of test flows
        test_flow_dur_sec (int): duration of test flows
        test_flow_delay_sec (int): delay of test flows in seconds
        test_flow_pkt_size (int): packet size of test flows
        prio_dscp_map (dict): priority to DSCP mapping
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """
    base_flow_config = snappi_extra_params.base_flow_config
    pytest_assert(base_flow_config is not None, "Cannot find base flow configuration")

    for prio in test_flow_prio_list:
        test_flow = testbed_config.flows.flow(name='{} Prio {}'.format(test_flow_name, prio))[-1]
        test_flow.tx_rx.port.tx_name = base_flow_config["tx_port_name"]
        test_flow.tx_rx.port.rx_name = base_flow_config["rx_port_name"]

        eth, ipv4 = test_flow.packet.ethernet().ipv4()
        eth.src.value = base_flow_config["tx_mac"]
        eth.dst.value = base_flow_config["rx_mac"]
        eth.pfc_queue.value = prio

        ipv4.src.value = base_flow_config["tx_port_config"].ip
        ipv4.dst.value = base_flow_config["rx_port_config"].ip
        ipv4.priority.choice = ipv4.priority.DSCP
        ipv4.priority.dscp.phb.values = prio_dscp_map[prio]
        ipv4.priority.dscp.ecn.value = (
            ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

        test_flow.size.fixed = test_flow_pkt_size
        test_flow.rate.percentage = test_flow_rate_percent
        test_flow.duration.fixed_seconds.seconds = test_flow_dur_sec
        test_flow.duration.fixed_seconds.delay.nanoseconds = int(sec_to_nanosec(test_flow_delay_sec))

        test_flow.metrics.enable = True
        test_flow.metrics.loss = True

        """ Set flow port config values """
        dut_port_config = base_flow_config["dut_port_config"]
        dut_port_config[0][str(base_flow_config["tx_port_config"].peer_port)].append(int(prio))
        dut_port_config[1][str(base_flow_config["rx_port_config"].peer_port)].append(int(prio))
        base_flow_config["dut_port_config"] = dut_port_config

    snappi_extra_params.base_flow_config = base_flow_config


def generate_background_flows(testbed_config,
                              bg_flow_name,
                              bg_flow_prio_list,
                              bg_flow_rate_percent,
                              bg_flow_dur_sec,
                              bg_flow_delay_sec,
                              bg_flow_pkt_size,
                              prio_dscp_map,
                              snappi_extra_params):
    """
    Generate background configurations of flows. Test flows and background flows are also known as data flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        bg_flow_name (str): name of background flow
        bg_flow_prio_list (list): list of background flow priorities
        bg_flow_rate_percent (int): rate percentage of background flows
        bg_flow_dur_sec (int): duration of background flows
        bg_flow_delay_sec (int): delay of background flows in seconds
        bg_flow_pkt_size (int): packet size of background flows
        prio_dscp_map (dict): priority to DSCP mapping
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """
    base_flow_config = snappi_extra_params.base_flow_config
    pytest_assert(base_flow_config is not None, "Cannot find base flow configuration")

    for prio in bg_flow_prio_list:
        bg_flow = testbed_config.flows.flow(name='{} Prio {}'.format(bg_flow_name, prio))[-1]
        bg_flow.tx_rx.port.tx_name = base_flow_config["tx_port_name"]
        bg_flow.tx_rx.port.rx_name = base_flow_config["rx_port_name"]

        eth, ipv4 = bg_flow.packet.ethernet().ipv4()
        eth.src.value = base_flow_config["tx_mac"]
        eth.dst.value = base_flow_config["rx_mac"]
        eth.pfc_queue.value = prio

        ipv4.src.value = base_flow_config["tx_port_config"].ip
        ipv4.dst.value = base_flow_config["rx_port_config"].ip
        ipv4.priority.choice = ipv4.priority.DSCP
        ipv4.priority.dscp.phb.values = prio_dscp_map[prio]
        ipv4.priority.dscp.ecn.value = (
            ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

        bg_flow.size.fixed = bg_flow_pkt_size
        bg_flow.rate.percentage = bg_flow_rate_percent
        bg_flow.duration.fixed_seconds.seconds = bg_flow_dur_sec
        bg_flow.duration.fixed_seconds.delay.nanoseconds = int(sec_to_nanosec(bg_flow_delay_sec))

        bg_flow.metrics.enable = True
        bg_flow.metrics.loss = True


def generate_pause_flows(testbed_config,
                         pause_flow_name,
                         pause_prio_list,
                         global_pause,
                         snappi_extra_params):
    """
    Generate configurations of pause flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        pause_flow_name (str): name of pause flow
        pause_prio_list (list): list of pause priorities
        global_pause (bool): global pause or per priority pause
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """
    base_flow_config = snappi_extra_params.base_flow_config
    pytest_assert(base_flow_config is not None, "Cannot find base flow configuration")

    pause_flow = testbed_config.flows.flow(name=pause_flow_name)[-1]
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
    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])
    pause_dur = 65535 * 64 * 8.0 / (speed_gbps * 1e9)
    pps = int(2 / pause_dur)

    pause_flow.rate.pps = pps
    pause_flow.size.fixed = 64
    pause_flow.duration.choice = pause_flow.duration.CONTINUOUS
    pause_flow.duration.continuous.delay.nanoseconds = 0

    pause_flow.metrics.enable = True
    pause_flow.metrics.loss = True


def run_traffic(api,
                config,
                data_flow_names,
                all_flow_names,
                exp_dur_sec,
                snappi_extra_params):

    """
    Run traffic and return per-flow statistics, and capture packets if needed.
    Args:
        api (obj): snappi session
        config (obj): experiment config (testbed config + flow config)
        data_flow_names (list): list of names of data (test and background) flows
        all_flow_names (list): list of names of all the flows
        exp_dur_sec (int): experiment duration in second
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
        per-flow statistics (list)
    """

    api.set_config(config)

    logger.info("Wait for Arp to Resolve ...")
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)

    pcap_type = snappi_extra_params.packet_capture_type

    if pcap_type != packet_capture.NO_CAPTURE:
        cs = api.capture_state()
        cs.port_names = snappi_extra_params.packet_capture_ports
        cs.state = cs.START
        api.set_capture_state(cs)

    logger.info("Starting transmit on all flows ...")
    ts = api.transmit_state()
    ts.state = ts.START
    api.set_transmit_state(ts)

    time.sleep(exp_dur_sec)

    attempts = 0
    max_attempts = 20

    while attempts < max_attempts:
        request = api.metrics_request()
        request.flow.flow_names = data_flow_names
        flow_metrics = api.get_metrics(request).flow_metrics

        # If all the data flows have stopped
        transmit_states = [metric.transmit for metric in flow_metrics]
        if len(flow_metrics) == len(data_flow_names) and\
           list(set(transmit_states)) == ['stopped']:
            time.sleep(SNAPPI_POLL_DELAY_SEC)
            break
        else:
            time.sleep(1)
            attempts += 1

    pytest_assert(attempts < max_attempts,
                  "Flows do not stop in {} seconds".format(max_attempts))

    if pcap_type != packet_capture.NO_CAPTURE:
        request = api.capture_request()
        request.port_name = snappi_extra_params.packet_capture_ports[0]
        cs = api.capture_state()
        cs.state = cs.STOP
        api.set_capture_state(cs)
        pcap_bytes = api.get_capture(request)
        with open(snappi_extra_params.packet_capture_file + ".pcapng", 'wb') as fid:
            fid.write(pcap_bytes.getvalue())

    # Dump per-flow statistics
    request = api.metrics_request()
    request.flow.flow_names = all_flow_names
    flow_metrics = api.get_metrics(request).flow_metrics
    logger.info("Stop transmit on all flows ...")
    ts = api.transmit_state()
    ts.state = ts.STOP
    api.set_transmit_state(ts)

    return flow_metrics


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
                           bg_flow_name,
                           bg_flow_rate_percent,
                           bg_flow_dur_sec,
                           bg_flow_pkt_size,
                           speed_gbps,
                           tolerance,
                           snappi_extra_params):
    """
    Verify background flow statistics. Background traffic on lossy priorities should not be dropped when there is no
    congestion, else some packets should be dropped if there is congestion.

    Args:
        flow_metrics (list): per-flow statistics
        bg_flow_name (str): name of the background flow
        bg_flow_rate_percent (int): background flow rate in percentage
        bg_flow_dur_sec (int): background data flow duration in second
        bg_flow_pkt_size (int): background data packet size in bytes
        speed_gbps (int): speed of the port in Gbps
        tolerance (float): tolerance for background flow deviation
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    for metric in flow_metrics:
        if bg_flow_name not in metric.name:
            continue

        tx_frames = metric.frames_tx
        rx_frames = metric.frames_rx

        exp_bg_flow_rx_pkts = bg_flow_rate_percent / 100.0 * speed_gbps \
            * 1e9 * bg_flow_dur_sec / 8.0 / bg_flow_pkt_size
        deviation = (rx_frames - exp_bg_flow_rx_pkts) / float(exp_bg_flow_rx_pkts)

        pytest_assert(tx_frames == rx_frames,
                      "{} should not have any dropped packet".format(metric.name))

        pytest_assert(abs(deviation) < tolerance,
                      "{} should receive {} packets (actual {})".format(metric.name, exp_bg_flow_rx_pkts, rx_frames))


def verify_basic_test_flow(flow_metrics,
                           test_flow_name,
                           test_flow_rate_percent,
                           test_flow_dur_sec,
                           test_flow_pkt_size,
                           speed_gbps,
                           tolerance,
                           test_flow_pause,
                           snappi_extra_params):
    """
    Verify basic test flow statistics from ixia. Test traffic on lossless priorities should not be dropped regardless
    of whether there is congestion or not.

    Args:
        flow_metrics (list): per-flow statistics
        test_flow_name (str): name of the test flow
        test_flow_rate_percent (int): test flow rate in percentage
        test_flow_dur_sec (int): test flow duration in second
        test_flow_pkt_size (int): test packet size in bytes
        speed_gbps (int): speed of the port in Gbps
        tolerance (float): tolerance for test flow deviation
        test_flow_pause (bool): whether test flow is expected to be paused
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    test_tx_frames = []

    for metric in flow_metrics:
        if test_flow_name not in metric.name:
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

            exp_test_flow_rx_pkts = test_flow_rate_percent / 100.0 * speed_gbps \
                * 1e9 * test_flow_dur_sec / 8.0 / test_flow_pkt_size
            deviation = (rx_frames - exp_test_flow_rx_pkts) / float(exp_test_flow_rx_pkts)
            pytest_assert(abs(deviation) < tolerance,
                          "{} should receive {} packets (actual {})".
                          format(test_flow_name, exp_test_flow_rx_pkts, rx_frames))

    snappi_extra_params.test_tx_frames = test_tx_frames


def verify_in_flight_buffer_pkts(duthost,
                                 flow_metrics,
                                 test_flow_name,
                                 test_flow_pkt_size,
                                 snappi_extra_params):
    """
    Verify in-flight TX bytes of test flows should be held by switch buffer unless PFC delay is applied
    for when test traffic is expected to be paused

    Args:
        duthost (obj): DUT host object
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    tx_frames_total = sum(metric.frames_tx for metric in flow_metrics if test_flow_name in metric.name)
    tx_bytes_total = tx_frames_total * test_flow_pkt_size
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
                dropped_packets = get_pg_dropped_packets(duthost, peer_port, prio)
                pytest_assert(dropped_packets > 0,
                              "Total TX dropped packets {} should be more than 0".
                              format(dropped_packets))
    else:
        pytest_assert(tx_bytes_total < dut_buffer_size,
                      "Total TX bytes {} should be smaller than DUT buffer size {}".
                      format(tx_bytes_total, dut_buffer_size))

        for peer_port, prios in dut_port_config[0].items():
            for prio in prios:
                dropped_packets = get_pg_dropped_packets(duthost, peer_port, prio)
                pytest_assert(dropped_packets == 0,
                              "Total TX dropped packets {} should be 0".
                              format(dropped_packets))


def verify_pause_frame_count(duthost,
                             snappi_extra_params):
    """
    Verify correct frame count for pause frames when the traffic is expected to be paused

    Args:
        duthost (obj): DUT host object
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')

    for peer_port, prios in dut_port_config[1].items():
        for prio in range(len(prios)):
            pfc_pause_rx_frames = get_pfc_frame_count(duthost, peer_port, prios[prio])
            pytest_assert(pfc_pause_rx_frames > 0,
                          "PFC pause frames with zero source MAC are not counted in the PFC counters")


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
            for prio in range(len(prios)):
                pfc_pause_rx_frames = get_pfc_frame_count(duthost, peer_port, prios[prio])
                pytest_assert(pfc_pause_rx_frames == 0,
                              "PFC pause frames with no bit set in the class enable vector should be dropped")


def verify_egress_queue_frame_count(duthost,
                                    snappi_extra_params):
    """
    Verify correct frame count for regular traffic from DUT egress queue

    Args:
        duthost (obj): DUT host object
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')
    set_class_enable_vec = snappi_extra_params.set_pfc_class_enable_vec
    test_tx_frames = snappi_extra_params.test_tx_frames

    if not set_class_enable_vec:
        for peer_port, prios in dut_port_config[1].items():
            for prio in range(len(prios)):
                total_egress_packets, _ = get_egress_queue_count(duthost, peer_port, prios[prio])
                pytest_assert(total_egress_packets == test_tx_frames[prio],
                              "Queue counters should increment for invalid PFC pause frames")
