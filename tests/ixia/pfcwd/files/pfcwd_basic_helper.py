import time
from math import ceil

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api
from tests.common.ixia.ixia_helpers import get_dut_port_id
from tests.common.ixia.common_helpers import pfc_class_enable_vector,\
    get_pfcwd_poll_interval, get_pfcwd_detect_time, get_pfcwd_restore_time,\
    enable_packet_aging, start_pfcwd

from abstract_open_traffic_generator.flow import DeviceTxRx, TxRx, Flow, Header,\
    Size, Rate,Duration, FixedSeconds, FixedPackets, PortTxRx, PfcPause
from abstract_open_traffic_generator.flow_ipv4 import Priority, Dscp
from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.control import State, ConfigState,\
    FlowTransmitState
from abstract_open_traffic_generator.result import FlowRequest

PAUSE_FLOW_NAME = "Pause Storm"
DATA_FLOW1_NAME = "Data Flow 1"
DATA_FLOW2_NAME = "Data Flow 2"
DATA_PKT_SIZE = 1024
IXIA_POLL_DELAY_SEC = 2
DEVIATION = 0.2

def run_pfcwd_basic_test(api,
                         testbed_config,
                         conn_data,
                         fanout_data,
                         duthost,
                         dut_port,
                         prio_list,
                         prio_dscp_map,
                         trigger_pfcwd):
    """
    Run a basic PFC watchdog test

    Args:
        api (obj): IXIA session
        testbed_config (obj): L2/L3 config of a T0 testbed
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        prio_list (list): priorities of data flows and pause storm
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

    Returns:
        N/A
    """

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    start_pfcwd(duthost)
    enable_packet_aging(duthost)

    """ Get the ID of the port to test """
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Fail to get ID for port {}'.format(dut_port))

    poll_interval_sec = get_pfcwd_poll_interval(duthost) / 1000.0
    detect_time_sec = get_pfcwd_detect_time(host_ans=duthost, intf=dut_port) / 1000.0
    restore_time_sec = get_pfcwd_restore_time(host_ans=duthost, intf=dut_port) / 1000.0

    if trigger_pfcwd:
        """ Large enough to trigger PFC watchdog """
        pfc_storm_dur_sec = ceil(detect_time_sec + poll_interval_sec + 0.1)

        flow1_delay_sec = restore_time_sec / 2
        flow1_dur_sec = pfc_storm_dur_sec

        """ Start data traffic 2 after PFC is restored """
        flow2_delay_sec = pfc_storm_dur_sec + restore_time_sec + poll_interval_sec
        flow2_dur_sec = 1

        flow1_max_loss_rate = 1
        flow1_min_loss_rate = 1- DEVIATION

    else:
        pfc_storm_dur_sec = detect_time_sec * 0.5
        flow1_delay_sec = pfc_storm_dur_sec * 0.1
        flow1_dur_sec = ceil(pfc_storm_dur_sec)

        """ Start data traffic 2 after the completion of data traffic 1 """
        flow2_delay_sec = flow1_delay_sec + flow1_dur_sec + 0.1
        flow2_dur_sec = 1

        flow1_max_loss_rate = 0
        flow1_min_loss_rate = 0

    exp_dur_sec = flow2_delay_sec + flow2_dur_sec + 1

    """ Generate traffic config """
    flows = __gen_traffic(testbed_config=testbed_config,
                          port_id=port_id,
                          pause_flow_name=PAUSE_FLOW_NAME,
                          pause_flow_dur_sec=pfc_storm_dur_sec,
                          data_flow_name_list=[DATA_FLOW1_NAME, DATA_FLOW2_NAME],
                          data_flow_delay_sec_list=[flow1_delay_sec, flow2_delay_sec],
                          data_flow_dur_sec_list=[flow1_dur_sec, flow2_dur_sec],
                          data_pkt_size=DATA_PKT_SIZE,
                          prio_list=prio_list,
                          prio_dscp_map=prio_dscp_map)

    """ Tgen config = testbed config + flow config """
    config = testbed_config
    config.flows = flows

    all_flow_names = [flow.name for flow in flows]

    flow_stats = __run_traffic(api=api,
                               config=config,
                               all_flow_names=all_flow_names,
                               exp_dur_sec=exp_dur_sec)

    __verify_results(rows=flow_stats,
                     data_flow_name_list=[DATA_FLOW1_NAME, DATA_FLOW2_NAME],
                     data_flow_min_loss_rate_list=[flow1_min_loss_rate, 0],
                     data_flow_max_loss_rate_list=[flow1_max_loss_rate, 0])

sec_to_nanosec = lambda x : x * 1e9

def __gen_traffic(testbed_config,
                  port_id,
                  pause_flow_name,
                  pause_flow_dur_sec,
                  data_flow_name_list,
                  data_flow_delay_sec_list,
                  data_flow_dur_sec_list,
                  data_pkt_size,
                  prio_list,
                  prio_dscp_map):
    """
    Generate configurations of flows, including data flows and pause storm.

    Args:
        testbed_config (obj): L2/L3 config of a T0 testbed
        port_id (int): ID of DUT port to test.
        pause_flow_name (str): name of pause storm
        pause_flow_dur_sec (float): duration of pause storm in second
        data_flow_name_list (list): list of data flow names
        data_flow_delay_sec_list (list): list of data flow start delays in second
        data_flow_dur_sec_list (list): list of data flow durations in second
        data_pkt_size (int): size of data packets in byte
        prio_list (list): priorities of data flows and pause storm
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        flows configurations (list): the list should have configurations of
        len(prio_list) * 2 data flows, and a pause storm.
    """
    result = list()

    rx_port_id = port_id
    tx_port_id = (port_id + 1) % len(testbed_config.devices)

    data_endpoint = DeviceTxRx(
        tx_device_names=[testbed_config.devices[tx_port_id].name],
        rx_device_names=[testbed_config.devices[rx_port_id].name],
    )

    """ PFC storm """
    pause_time = []
    for x in range(8):
        if x in prio_list:
            pause_time.append('ffff')
        else:
            pause_time.append('0000')

    vector = pfc_class_enable_vector(prio_list)

    pause_pkt = Header(PfcPause(
        dst=FieldPattern(choice='01:80:C2:00:00:01'),
        src=FieldPattern(choice='00:00:fa:ce:fa:ce'),
        class_enable_vector=FieldPattern(choice=vector),
        pause_class_0=FieldPattern(choice=pause_time[0]),
        pause_class_1=FieldPattern(choice=pause_time[1]),
        pause_class_2=FieldPattern(choice=pause_time[2]),
        pause_class_3=FieldPattern(choice=pause_time[3]),
        pause_class_4=FieldPattern(choice=pause_time[4]),
        pause_class_5=FieldPattern(choice=pause_time[5]),
        pause_class_6=FieldPattern(choice=pause_time[6]),
        pause_class_7=FieldPattern(choice=pause_time[7]),
    ))

    pause_src_point = PortTxRx(tx_port_name=testbed_config.ports[rx_port_id].name,
                               rx_port_name=testbed_config.ports[tx_port_id].name)

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])
    pause_dur = 65535 * 64 * 8.0 / (speed_gbps * 1e9)
    pps = int(2 / pause_dur)
    pause_pkt_cnt = pps * pause_flow_dur_sec

    pause_flow = Flow(
        name=pause_flow_name,
        tx_rx=TxRx(pause_src_point),
        packet=[pause_pkt],
        size=Size(64),
        rate=Rate('pps', value=pps),
        duration=Duration(FixedPackets(packets=pause_pkt_cnt, delay=0))
    )

    result.append(pause_flow)

    data_flow_rate_percent = int(100 / len(prio_list))

    """ For each data flow """
    for i in range(len(data_flow_name_list)):

        """ For each priority """
        for prio in prio_list:
            ip_prio = Priority(Dscp(phb=FieldPattern(choice=prio_dscp_map[prio]),
                                    ecn=FieldPattern(choice=Dscp.ECN_CAPABLE_TRANSPORT_1)))
            pfc_queue = FieldPattern([prio])

            data_flow = Flow(
                name='{} Prio {}'.format(data_flow_name_list[i], prio),
                tx_rx=TxRx(data_endpoint),
                packet=[
                    Header(choice=EthernetHeader(pfc_queue=pfc_queue)),
                    Header(choice=Ipv4Header(priority=ip_prio))
                ],
                size=Size(data_pkt_size),
                rate=Rate('line', data_flow_rate_percent),
                duration=Duration(FixedSeconds(seconds=data_flow_dur_sec_list[i],
                                               delay=sec_to_nanosec(data_flow_delay_sec_list[i]),
                                               delay_unit='nanoseconds'))
            )

            result.append(data_flow)

    return result

def __run_traffic(api, config, all_flow_names, exp_dur_sec):
    """
    Run traffic and dump per-flow statistics

    Args:
        api (obj): IXIA session
        config (obj): experiment config (testbed config + flow config)
        all_flow_names (list): list of names of all the flows
        exp_dur_sec (float): experiment duration in second

    Returns:
        per-flow statistics (list)
    """
    api.set_state(State(ConfigState(config=config, state='set')))
    api.set_state(State(FlowTransmitState(state='start')))
    time.sleep(exp_dur_sec)

    attempts = 0
    max_attempts = 20

    while attempts < max_attempts:
        rows = api.get_flow_results(FlowRequest(flow_names=all_flow_names))
        """ If all the flows have stopped """
        transmit_states = [row['transmit'] for row in rows]
        if len(rows) == len(all_flow_names) and\
           list(set(transmit_states)) == ['stopped']:
            time.sleep(IXIA_POLL_DELAY_SEC)
            break
        else:
            time.sleep(1)
            attempts += 1

    pytest_assert(attempts < max_attempts,
                  "Flows do not stop in {} seconds".format(max_attempts))

    """ Dump per-flow statistics """
    rows = api.get_flow_results(FlowRequest(flow_names=all_flow_names))
    api.set_state(State(FlowTransmitState(state='stop')))

    return rows

def __verify_results(rows,
                     data_flow_name_list,
                     data_flow_min_loss_rate_list,
                     data_flow_max_loss_rate_list):
    """
    Verify if we get expected experiment results

    Args:
        rows (list): per-flow statistics
        data_flow_name_list (list): list of data flow names
        data_flow_min_loss_rate_list (list): list of data flow min loss rates
        data_flow_max_loss_rate_list (list): list of data flow max loss rates

    Returns:
        N/A
    """
    num_data_flows = len(data_flow_name_list)
    data_flow_tx_frames_list = num_data_flows * [0]
    data_flow_rx_frames_list = num_data_flows * [0]

    for row in rows:
        flow_name = row['name']
        tx_frames = row['frames_tx']
        rx_frames = row['frames_rx']

        for i in range(num_data_flows):
            if data_flow_name_list[i] in flow_name:
                data_flow_tx_frames_list[i] += tx_frames
                data_flow_rx_frames_list[i] += rx_frames

    for i in range(num_data_flows):
        loss_rate = 1 - float(data_flow_rx_frames_list[i]) / data_flow_tx_frames_list[i]
        min_loss_rate = data_flow_min_loss_rate_list[i]
        max_loss_rate = data_flow_max_loss_rate_list[i]

        pytest_assert(loss_rate <= max_loss_rate and loss_rate >= min_loss_rate,
                      'Loss rate of {} ({}) should be in [{}, {}]'.format(
                      data_flow_name_list[i], loss_rate, min_loss_rate, max_loss_rate))
