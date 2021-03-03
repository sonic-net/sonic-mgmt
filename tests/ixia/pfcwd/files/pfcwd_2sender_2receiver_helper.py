import time
from math import ceil
from itertools import permutations

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api
from tests.common.ixia.ixia_helpers import get_dut_port_id
from tests.common.ixia.common_helpers import pfc_class_enable_vector,\
    start_pfcwd, enable_packet_aging, get_pfcwd_poll_interval, get_pfcwd_detect_time

from abstract_open_traffic_generator.flow import DeviceTxRx, TxRx, Flow, Header,\
    Size, Rate, Duration, FixedSeconds, FixedPackets, PortTxRx, PfcPause
from abstract_open_traffic_generator.flow_ipv4 import Priority, Dscp
from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.control import State, ConfigState, FlowTransmitState
from abstract_open_traffic_generator.result import FlowRequest

PAUSE_FLOW_NAME = 'Pause Storm'
TEST_FLOW_NAME = 'Test Flow'
TEST_FLOW_AGGR_RATE_PERCENT = 45
BG_FLOW_NAME = 'Background Flow'
BG_FLOW_AGGR_RATE_PERCENT = 45
DATA_PKT_SIZE = 1024
IXIA_POLL_DELAY_SEC = 2
TOLERANCE_THRESHOLD = 0.05

def run_pfcwd_2sender_2receiver_test(api,
                                     testbed_config,
                                     conn_data,
                                     fanout_data,
                                     duthost,
                                     dut_port,
                                     pause_prio_list,
                                     test_prio_list,
                                     bg_prio_list,
                                     prio_dscp_map,
                                     trigger_pfcwd):

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    pytest_assert(len(testbed_config.devices) >= 3,
                  "This test requires at least 3 hosts")

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

    if trigger_pfcwd:
        pfc_storm_dur_sec = poll_interval_sec + detect_time_sec

    else:
        pfc_storm_dur_sec = 0.5 * detect_time_sec

    exp_dur_sec = ceil(pfc_storm_dur_sec + 1)

    """ Rate percent must be an integer """
    test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT / 2.0 / len(test_prio_list))
    bg_flow_rate_percent = int(BG_FLOW_AGGR_RATE_PERCENT / 2.0 / len(bg_prio_list))

    """ Generate traffic config """
    flows = __gen_traffic(testbed_config=testbed_config,
                          port_id=port_id,
                          pause_flow_name=PAUSE_FLOW_NAME,
                          pause_prio_list=pause_prio_list,
                          test_flow_name=TEST_FLOW_NAME,
                          test_flow_prio_list=test_prio_list,
                          test_flow_rate_percent=test_flow_rate_percent,
                          bg_flow_name=BG_FLOW_NAME,
                          bg_flow_prio_list=bg_prio_list,
                          bg_flow_rate_percent=bg_flow_rate_percent,
                          data_flow_dur_sec=exp_dur_sec,
                          pfc_storm_dur_sec=pfc_storm_dur_sec,
                          data_pkt_size=DATA_PKT_SIZE,
                          prio_dscp_map=prio_dscp_map)

    """ Tgen config = testbed config + flow config """
    config = testbed_config
    config.flows = flows

    all_flow_names = [flow.name for flow in flows]

    flow_stats = __run_traffic(api=api,
                               config=config,
                               all_flow_names=all_flow_names,
                               exp_dur_sec=exp_dur_sec)

    speed_str = config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])

    __verify_results(rows=flow_stats,
                     speed_gbps=speed_gbps,
                     pause_flow_name=PAUSE_FLOW_NAME,
                     test_flow_name=TEST_FLOW_NAME,
                     bg_flow_name=BG_FLOW_NAME,
                     test_flow_rate_percent=test_flow_rate_percent,
                     bg_flow_rate_percent=bg_flow_rate_percent,
                     data_flow_dur_sec=exp_dur_sec,
                     data_pkt_size=DATA_PKT_SIZE,
                     trigger_pfcwd=trigger_pfcwd,
                     pause_port_id=port_id,
                     tolerance=TOLERANCE_THRESHOLD)


def __data_flow_name(name_prefix, src_id, dst_id, prio):
    return "{} {} -> {} Prio {}".format(name_prefix, src_id, dst_id, prio)

def __data_flow_src(flow_name):
    words = flow_name.split()
    index = words.index('->')
    return words[index-1]

def __data_flow_dst(flow_name):
    words = flow_name.split()
    index = words.index('->')
    return words[index+1]

def __gen_traffic(testbed_config,
                  port_id,
                  pause_flow_name,
                  pause_prio_list,
                  test_flow_name,
                  test_flow_prio_list,
                  test_flow_rate_percent,
                  bg_flow_name,
                  bg_flow_prio_list,
                  bg_flow_rate_percent,
                  data_flow_dur_sec,
                  pfc_storm_dur_sec,
                  data_pkt_size,
                  prio_dscp_map):

    result = list()

    """ Generate a PFC pause storm """
    pause_port_id = port_id
    pause_flow = __gen_pause_flow(testbed_config=testbed_config,
                                  src_port_id=pause_port_id,
                                  flow_name=pause_flow_name,
                                  pause_prio_list=pause_prio_list,
                                  flow_dur_sec=pfc_storm_dur_sec)

    result.append(pause_flow)

    """ Generate one-to-two and two-to-one data flows """
    one_port_id_list = [(port_id - 1) % len(testbed_config.devices)]
    two_port_id_list = [port_id, (port_id + 1) % len(testbed_config.devices)]

    perm = permutations([one_port_id_list, two_port_id_list])

    for src_port_id_list, dst_port_id_list in list(perm):
        test_flows = __gen_data_flows(testbed_config=testbed_config,
                                      src_port_id_list=src_port_id_list,
                                      dst_port_id_list=dst_port_id_list,
                                      flow_name_prefix=TEST_FLOW_NAME,
                                      flow_prio_list=test_flow_prio_list,
                                      flow_rate_percent=test_flow_rate_percent,
                                      flow_dur_sec=data_flow_dur_sec,
                                      data_pkt_size=data_pkt_size,
                                      prio_dscp_map=prio_dscp_map)

        result.extend(test_flows)

        bg_flows = __gen_data_flows(testbed_config=testbed_config,
                                    src_port_id_list=src_port_id_list,
                                    dst_port_id_list=dst_port_id_list,
                                    flow_name_prefix=BG_FLOW_NAME,
                                    flow_prio_list=bg_flow_prio_list,
                                    flow_rate_percent=bg_flow_rate_percent,
                                    flow_dur_sec=data_flow_dur_sec,
                                    data_pkt_size=data_pkt_size,
                                    prio_dscp_map=prio_dscp_map)

        result.extend(bg_flows)

    return result

def __gen_data_flows(testbed_config,
                     src_port_id_list,
                     dst_port_id_list,
                     flow_name_prefix,
                     flow_prio_list,
                     flow_rate_percent,
                     flow_dur_sec,
                     data_pkt_size,
                     prio_dscp_map):

    flows = []

    for src_port_id in src_port_id_list:
        for dst_port_id in dst_port_id_list:
            for prio in flow_prio_list:
                flow = __gen_data_flow(testbed_config=testbed_config,
                                       src_port_id=src_port_id,
                                       dst_port_id=dst_port_id,
                                       flow_name_prefix=flow_name_prefix,
                                       flow_prio=prio,
                                       flow_rate_percent=flow_rate_percent,
                                       flow_dur_sec=flow_dur_sec,
                                       data_pkt_size=data_pkt_size,
                                       prio_dscp_map=prio_dscp_map)
                flows.append(flow)

    return flows

def __gen_data_flow(testbed_config,
                    src_port_id,
                    dst_port_id,
                    flow_name_prefix,
                    flow_prio,
                    flow_rate_percent,
                    flow_dur_sec,
                    data_pkt_size,
                    prio_dscp_map):

    data_endpoint = DeviceTxRx(
        tx_device_names=[testbed_config.devices[src_port_id].name],
        rx_device_names=[testbed_config.devices[dst_port_id].name],
    )

    ip_prio = Priority(Dscp(phb=FieldPattern(choice=prio_dscp_map[flow_prio]),
                            ecn=FieldPattern(choice=Dscp.ECN_CAPABLE_TRANSPORT_1)))

    pfc_queue = FieldPattern([flow_prio])

    flow_name = __data_flow_name(name_prefix=flow_name_prefix,
                                 src_id=src_port_id,
                                 dst_id=dst_port_id,
                                 prio=flow_prio)

    flow = Flow(
        name=flow_name,
        tx_rx=TxRx(data_endpoint),
        packet=[
            Header(choice=EthernetHeader(pfc_queue=pfc_queue)),
            Header(choice=Ipv4Header(priority=ip_prio))
        ],
        size=Size(data_pkt_size),
        rate=Rate('line', flow_rate_percent),
        duration=Duration(FixedSeconds(seconds=flow_dur_sec))
    )

    return flow

def __gen_pause_flow(testbed_config,
                     src_port_id,
                     flow_name,
                     pause_prio_list,
                     flow_dur_sec):

    pause_time = []
    for x in range(8):
        if x in pause_prio_list:
            pause_time.append('ffff')
        else:
            pause_time.append('0000')

    vector = pfc_class_enable_vector(pause_prio_list)

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


    dst_port_id = (src_port_id + 1) % len(testbed_config.devices)
    pause_src_point = PortTxRx(tx_port_name=testbed_config.ports[src_port_id].name,
                               rx_port_name=testbed_config.ports[dst_port_id].name)

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])
    pause_dur = 65535 * 64 * 8.0 / (speed_gbps * 1e9)
    pps = int(2 / pause_dur)
    pkt_cnt = pps * flow_dur_sec

    pause_flow = Flow(
        name=flow_name,
        tx_rx=TxRx(pause_src_point),
        packet=[pause_pkt],
        size=Size(64),
        rate=Rate('pps', value=pps),
        duration=Duration(FixedPackets(packets=pkt_cnt, delay=0))
    )

    return pause_flow

def __run_traffic(api, config, all_flow_names, exp_dur_sec):
    api.set_state(State(ConfigState(config=config, state='set')))
    api.set_state(State(FlowTransmitState(state='start')))
    time.sleep(exp_dur_sec)

    attempts = 0
    max_attempts = 20

    while attempts < max_attempts:
        rows = api.get_flow_results(FlowRequest(flow_names=all_flow_names))

        """ If all the data flows have stopped """
        transmit_states = [row['transmit'] for row in rows]
        if len(rows) == len(all_flow_names) and\
           list(set(transmit_states)) == ['stopped']:
            time.sleep(IXIA_POLL_DELAY_SEC)
            break
        else:
            time.sleep(1)
            attempts += 1

    if attempts >= max_attempts:
        api.set_state(State(FlowTransmitState(state='stop')))
        pytest_assert(attempts < max_attempts,
                      "Flows do not stop in {} seconds".format(max_attempts))

    """ Dump per-flow statistics """
    rows = api.get_flow_results(FlowRequest(flow_names=all_flow_names))
    api.set_state(State(FlowTransmitState(state='stop')))

    return rows

def __verify_results(rows,
                     speed_gbps,
                     pause_flow_name,
                     test_flow_name,
                     bg_flow_name,
                     test_flow_rate_percent,
                     bg_flow_rate_percent,
                     data_flow_dur_sec,
                     data_pkt_size,
                     trigger_pfcwd,
                     pause_port_id,
                     tolerance):

    for row in rows:
        flow_name = row['name']
        tx_frames = row['frames_tx']
        rx_frames = row['frames_rx']

        if pause_flow_name in flow_name:
            """ PFC pause storm """
            pytest_assert(tx_frames > 0 and rx_frames == 0,
                          "All the PFC packets should be dropped")

        elif bg_flow_name in flow_name:
            """ Background flows """
            pytest_assert(tx_frames == rx_frames,
                          '{} should not have any dropped packet'.format(flow_name))

            exp_bg_flow_rx_pkts =  bg_flow_rate_percent / 100.0 * speed_gbps \
                * 1e9 * data_flow_dur_sec / 8.0 / data_pkt_size
            deviation = (rx_frames - exp_bg_flow_rx_pkts) / float(exp_bg_flow_rx_pkts)
            pytest_assert(abs(deviation) < tolerance,
                          '{} should receive {} packets (actual {})'.\
                          format(flow_name, exp_bg_flow_rx_pkts, rx_frames))

        elif test_flow_name in flow_name:
            """ Test flows """
            src_port_id = int(__data_flow_src(flow_name))
            dst_port_id = int(__data_flow_dst(flow_name))

            exp_test_flow_rx_pkts =  test_flow_rate_percent / 100.0 * speed_gbps \
                * 1e9 * data_flow_dur_sec / 8.0 / data_pkt_size

            if trigger_pfcwd and\
               (src_port_id == pause_port_id or dst_port_id == pause_port_id):
                """ Once PFC watchdog is triggered, it will impact bi-directional traffic """
                pytest_assert(tx_frames > rx_frames,
                              '{} should have dropped packets'.format(flow_name))

            elif not trigger_pfcwd and dst_port_id == pause_port_id:
                """ This test flow is delayed by PFC storm """
                pytest_assert(tx_frames == rx_frames,
                              '{} should not have any dropped packet'.format(flow_name))
                pytest_assert(rx_frames < exp_test_flow_rx_pkts,
                              '{} shoudl receive less than {} packets (actual {})'.\
                              format(flow_name, exp_test_flow_rx_pkts, rx_frames))

            else:
                """ Otherwise, the test flow is not impacted by PFC storm """
                pytest_assert(tx_frames == rx_frames,
                              '{} should not have any dropped packet'.format(flow_name))

                deviation = (rx_frames - exp_test_flow_rx_pkts) / float(exp_test_flow_rx_pkts)
                pytest_assert(abs(deviation) < tolerance,
                              '{} should receive {} packets (actual {})'.\
                              format(flow_name, exp_test_flow_rx_pkts, rx_frames))
