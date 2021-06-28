import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api
from tests.common.ixia.ixia_helpers import get_dut_port_id
from tests.common.ixia.common_helpers import start_pfcwd, stop_pfcwd
from tests.common.ixia.port import select_ports, select_tx_port

from abstract_open_traffic_generator.flow import PortTxRx, TxRx, Flow, Header,\
    Size, Rate, Duration, FixedSeconds
from abstract_open_traffic_generator.flow_ipv4 import Priority, Dscp
from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.control import State, ConfigState,\
    FlowTransmitState
from abstract_open_traffic_generator.result import FlowRequest

DATA_FLOW_NAME = "Data Flow"
DATA_PKT_SIZE = 1024
DATA_FLOW_DURATION_SEC = 15
PFCWD_START_DELAY_SEC = 3
IXIA_POLL_DELAY_SEC = 2
TOLERANCE_THRESHOLD = 0.05

def run_pfcwd_runtime_traffic_test(api,
                                   testbed_config,
                                   port_config_list,
                                   conn_data,
                                   fanout_data,
                                   duthost,
                                   dut_port,
                                   prio_list,
                                   prio_dscp_map):
    """
    Test PFC watchdog's impact on runtime traffic

    Args:
        api (obj): IXIA session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        prio_list (list): priorities of data flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """
    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    stop_pfcwd(duthost)

    """ Get the ID of the port to test """
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Fail to get ID for port {}'.format(dut_port))

    flows = __gen_traffic(testbed_config=testbed_config,
                          port_config_list=port_config_list,
                          port_id=port_id,
                          data_flow_name=DATA_FLOW_NAME,
                          data_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                          data_pkt_size=DATA_PKT_SIZE,
                          prio_list=prio_list,
                          prio_dscp_map=prio_dscp_map)

    """ Tgen config = testbed config + flow config """
    config = testbed_config
    config.flows = flows

    all_flow_names = [flow.name for flow in flows]

    flow_stats = __run_traffic(api=api,
                               config=config,
                               duthost=duthost,
                               all_flow_names=all_flow_names,
                               pfcwd_start_delay_sec=PFCWD_START_DELAY_SEC,
                               exp_dur_sec=DATA_FLOW_DURATION_SEC)

    speed_str = config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])

    __verify_results(rows=flow_stats,
                     speed_gbps=speed_gbps,
                     data_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                     data_pkt_size=DATA_PKT_SIZE,
                     tolerance=TOLERANCE_THRESHOLD)

def __gen_traffic(testbed_config,
                  port_config_list,
                  port_id,
                  data_flow_name,
                  data_flow_dur_sec,
                  data_pkt_size,
                  prio_list,
                  prio_dscp_map):
    """
    Generate configurations of flows

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test.
        data_flow_name (str): data flow name
        data_flow_dur_sec (int): duration of data flows in second
        data_pkt_size (int): size of data packets in byte
        prio_list (list): priorities of data flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        flows configurations (list): the list should have configurations of
        len(prio_list) data flows
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

    data_endpoint = PortTxRx(tx_port_name=testbed_config.ports[tx_port_id].name,
                             rx_port_name=testbed_config.ports[rx_port_id].name)
    data_flow_rate_percent = int(100 / len(prio_list))

    """ For each priority """
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
            name='{} Prio {}'.format(data_flow_name, prio),
            tx_rx=TxRx(data_endpoint),
            packet=[Header(choice=eth_hdr), Header(choice=ipv4_hdr)],
            size=Size(data_pkt_size),
            rate=Rate('line', data_flow_rate_percent),
            duration=Duration(FixedSeconds(seconds=data_flow_dur_sec))
        )

        result.append(data_flow)

    return result

def __run_traffic(api, config, duthost, all_flow_names, pfcwd_start_delay_sec, exp_dur_sec):
    """
    Start traffic at time 0 and enable PFC watchdog at pfcwd_start_delay_sec

    Args:
        api (obj): IXIA session
        config (obj): experiment config (testbed config + flow config)
        duthost (Ansible host instance): device under test
        all_flow_names (list): list of names of all the flows
        pfcwd_start_delay_sec (int): PFC watchdog start delay in second
        exp_dur_sec (int): experiment duration in second

    Returns:
        per-flow statistics (list)
    """

    api.set_state(State(ConfigState(config=config, state='set')))
    api.set_state(State(FlowTransmitState(state='start')))

    time.sleep(pfcwd_start_delay_sec)
    start_pfcwd(duthost)
    time.sleep(exp_dur_sec - pfcwd_start_delay_sec)

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

def __verify_results(rows, speed_gbps, data_flow_dur_sec, data_pkt_size, tolerance):
    """
    Verify if we get expected experiment results

    Args:
        rows (list): per-flow statistics
        speed_gbps (int): link speed in Gbps
        data_flow_dur_sec (int): duration of data flows in second
        data_pkt_size (int): size of data packets in byte
        tolerance (float): maximum allowable deviation

    Returns:
        N/A
    """
    data_flow_rate_percent = int(100 / len(rows))

    for row in rows:
        flow_name = row['name']
        tx_frames = row['frames_tx']
        rx_frames = row['frames_rx']

        pytest_assert(tx_frames == rx_frames, "{} packets of {} are dropped".\
                      format(tx_frames-rx_frames, flow_name))

        exp_rx_pkts =  data_flow_rate_percent / 100.0 * speed_gbps \
            * 1e9 * data_flow_dur_sec / 8.0 / data_pkt_size

        deviation = (rx_frames - exp_rx_pkts) / float(exp_rx_pkts)
        pytest_assert(abs(deviation) < tolerance,
                      "{} should receive {} packets (actual {})".\
                      format(flow_name, exp_rx_pkts, rx_frames))
