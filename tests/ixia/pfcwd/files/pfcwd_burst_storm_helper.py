import time
from math import ceil

from tests.common.helpers.assertions import pytest_assert
from tests.common.ixia.ixia_helpers import get_dut_port_id
from tests.common.ixia.common_helpers import pfc_class_enable_vector,\
    get_pfcwd_poll_interval, get_pfcwd_detect_time, get_pfcwd_restore_time,\
    enable_packet_aging, start_pfcwd
from tests.common.ixia.port import select_ports, select_tx_port

from abstract_open_traffic_generator.flow import TxRx, Flow, Header, Size,\
    Rate,Duration, FixedSeconds, FixedPackets, PortTxRx, PfcPause
from abstract_open_traffic_generator.flow_ipv4 import Priority, Dscp
from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.control import State, ConfigState,\
    FlowTransmitState
from abstract_open_traffic_generator.result import FlowRequest

PAUSE_FLOW_PREFIX = "Pause Storm"
DATA_FLOW_PREFIX = "Data Flow"
BURST_EVENTS = 15
DATA_PKT_SIZE = 1024
IXIA_POLL_DELAY_SEC = 2

def run_pfcwd_burst_storm_test(api,
                               testbed_config,
                               port_config_list,
                               conn_data,
                               fanout_data,
                               duthost,
                               dut_port,
                               prio_list,
                               prio_dscp_map):
    """
    Test PFC watchdog under bursty PFC storms

    Args:
        api (obj): IXIA session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        prio_list (list): priorities to generate PFC storms and data traffic
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

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

    burst_cycle_sec = poll_interval_sec + detect_time_sec + restore_time_sec + 0.1
    data_flow_dur_sec = ceil(burst_cycle_sec * BURST_EVENTS)
    pause_flow_dur_sec = poll_interval_sec * 0.5
    pause_flow_gap_sec = burst_cycle_sec - pause_flow_dur_sec

    flows = __gen_traffic(testbed_config=testbed_config,
                          port_config_list=port_config_list,
                          port_id=port_id,
                          pause_flow_prefix=PAUSE_FLOW_PREFIX,
                          pause_flow_dur_sec=pause_flow_dur_sec,
                          pause_flow_count = BURST_EVENTS,
                          pause_flow_gap_sec=pause_flow_gap_sec,
                          data_flow_prefix=DATA_FLOW_PREFIX,
                          data_flow_dur_sec=data_flow_dur_sec,
                          data_pkt_size=DATA_PKT_SIZE,
                          prio_list=prio_list,
                          prio_dscp_map=prio_dscp_map)

    """ Tgen config = testbed config + flow config """
    config = testbed_config
    config.flows = flows

    all_flow_names = [flow.name for flow in flows]
    exp_dur_sec = BURST_EVENTS * poll_interval_sec + 1

    flow_stats = __run_traffic(api=api,
                               config=config,
                               all_flow_names=all_flow_names,
                               exp_dur_sec=exp_dur_sec)

    __verify_results(rows=flow_stats,
                     data_flow_prefix=DATA_FLOW_PREFIX,
                     pause_flow_prefix=PAUSE_FLOW_PREFIX)

sec_to_nanosec = lambda x : x * 1e9

def __gen_traffic(testbed_config,
                  port_config_list,
                  port_id,
                  pause_flow_prefix,
                  pause_flow_count,
                  pause_flow_dur_sec,
                  pause_flow_gap_sec,
                  data_flow_prefix,
                  data_flow_dur_sec,
                  data_pkt_size,
                  prio_list,
                  prio_dscp_map):
    """
    Generate flow configurations

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test.
        pause_flow_prefix (str): prefix of names of PFC pause storms
        pause_flow_count (int): number of PFC pause storms
        pause_flow_dur_sec (float): duration of each PFC pause storm
        pause_flow_gap_sec (float): gap between PFC pause storms
        data_flow_prefix (str): prefix of names of data flows
        data_flow_dur_sec (int): duration of all the data flows
        data_pkt_size (int): data packet size in bytes
        prio_list (list): priorities to generate PFC storms and data traffic
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        flows configurations (list)
    """
    result = list()

    rx_port_id = port_id
    tx_port_id_list, rx_port_id_list = select_ports(port_config_list=port_config_list,
                                                    pattern="many to one",
                                                    rx_port_id=rx_port_id)
    pytest_assert(len(tx_port_id_list) > 0, "Cannot find any TX ports")
    tx_port_id = select_tx_port(tx_port_id_list=tx_port_id_list,
                                rx_port_id=rx_port_id)
    pytest_assert(tx_port_id is not None, "Cannot find a suitable TX port")

    tx_port_config = next((x for x in port_config_list if x.id == tx_port_id), None)
    rx_port_config = next((x for x in port_config_list if x.id == rx_port_id), None)

    tx_mac = tx_port_config.mac
    if tx_port_config.gateway == rx_port_config.gateway and \
       tx_port_config.prefix_len == rx_port_config.prefix_len:
        """ If soruce and destination port are in the same subnet """
        rx_mac = rx_port_config.mac
    else:
        rx_mac = tx_port_config.gateway_mac

    """ Generate long-lived data flows, one for each priority """
    data_flow_rate_percent = int(100 / len(prio_list))
    data_endpoint = PortTxRx(tx_port_name=testbed_config.ports[tx_port_id].name,
                             rx_port_name=testbed_config.ports[rx_port_id].name)

    for prio in prio_list:
        eth_hdr = EthernetHeader(src=FieldPattern(tx_mac),
                                 dst=FieldPattern(rx_mac),
                                 pfc_queue=FieldPattern([prio]))

        ip_prio = Priority(Dscp(phb=FieldPattern(choice=prio_dscp_map[prio]),
                                ecn=FieldPattern(choice=Dscp.ECN_CAPABLE_TRANSPORT_1)))

        ipv4_hdr = Ipv4Header(src=FieldPattern(tx_port_config.ip),
                              dst=FieldPattern(rx_port_config.ip),
                              priority=ip_prio)

        data_flow = Flow(
            name='{} Prio {}'.format(data_flow_prefix, prio),
            tx_rx=TxRx(data_endpoint),
            packet=[Header(choice=eth_hdr), Header(choice=ipv4_hdr)],
            size=Size(data_pkt_size),
            rate=Rate('line', data_flow_rate_percent),
            duration=Duration(FixedSeconds(seconds=data_flow_dur_sec, delay=0))
        )

        result.append(data_flow)

    """ Generate a series of PFC storms """
    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])
    pause_dur = 65535 * 64 * 8.0 / (speed_gbps * 1e9)
    pause_pps = int(2 / pause_dur)
    pause_pkt_cnt = pause_pps * pause_flow_dur_sec
    pause_endpoint = PortTxRx(tx_port_name=testbed_config.ports[rx_port_id].name,
                              rx_port_name=testbed_config.ports[tx_port_id].name)

    for id in range(pause_flow_count):
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

        pause_flow_start_time = id * (pause_flow_dur_sec + pause_flow_gap_sec)
        pause_flow = Flow(
            name="{} {}".format(pause_flow_prefix, id),
            tx_rx=TxRx(pause_endpoint),
            packet=[pause_pkt],
            size=Size(64),
            rate=Rate('pps', value=pause_pps),
            duration=Duration(FixedPackets(packets=pause_pkt_cnt,
                                           delay=sec_to_nanosec(pause_flow_start_time),
                                           delay_unit='nanoseconds'))
        )

        result.append(pause_flow)

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

def __verify_results(rows, data_flow_prefix, pause_flow_prefix):
    """
    Verify if we get expected experiment results

    Args:
        rows (list): per-flow statistics
        data_flow_prefix (str): prefix of names of data flows
        pause_flow_prefix (str): prefix of names of PFC pause storms

    Returns:
        N/A
    """
    for row in rows:
        flow_name = row['name']
        tx_frames = row['frames_tx']
        rx_frames = row['frames_rx']

        if data_flow_prefix in flow_name:
            """ Data flow """
            pytest_assert(tx_frames > 0 and rx_frames == tx_frames,
                          "No data packet should be dropped")

        elif pause_flow_prefix in flow_name:
            """ PFC pause storm """
            pytest_assert(tx_frames > 0 and rx_frames == 0,
                          "All the PFC packets should be dropped")
