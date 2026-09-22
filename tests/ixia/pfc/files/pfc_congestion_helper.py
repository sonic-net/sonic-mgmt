import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.ixia.ixia_helpers import get_dut_port_id
from tests.common.ixia.common_helpers import \
    stop_pfcwd, disable_packet_aging
from tests.common.ixia.port import select_ports

from abstract_open_traffic_generator.flow import (
    TxRx, Flow, Header, Size, Rate, Duration, FixedSeconds, PortTxRx)
from abstract_open_traffic_generator.flow_ipv4 import Priority, Dscp
from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.control import (
    State, ConfigState, FlowTransmitState)
from abstract_open_traffic_generator.result import FlowRequest

LOSSLESS_FLOW_NAME = 'Test Flow'
FLOW_RATE_PERCENT = 80
LOSSY_FLOW_NAME = 'Lossy Flow'
DATA_PKT_SIZE = 1024
DATA_FLOW_DURATION_SEC = 5
IXIA_POLL_DELAY_SEC = 2


def run_pfc_congestion(
        api,
        testbed_config,
        port_config_list,
        conn_data,
        fanout_data,
        duthost,
        dut_port,
        lossless_prio_list,
        lossy_prio_list,
        prio_dscp_map):
    """
    Run a PFC congestion test.
    - Inject both lossless and lossy traffic with combined rate above the
      line rate
        - The combined rate is above linerate.
        - The individual rate is below the linerate.
    - Expect the lossless traffic to not have any drops.
    - The lossy traffic should be dropped depending on the rate.

    Args:
        api (obj): IXIA session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        lossless_prio_list (list): priorities of test flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    pytest_assert(
        testbed_config is not None,
        'Fail to get L2/3 testbed config')

    stop_pfcwd(duthost)
    disable_packet_aging(duthost)

    """ Get the ID of the port to test """
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Fail to get ID for port {}'.format(dut_port))

    """ Rate percent must be an integer """
    flow_rate_percent = int(FLOW_RATE_PERCENT)

    pkt_size = DATA_PKT_SIZE

    """ Generate traffic config """
    flows = __gen_traffic(testbed_config=testbed_config,
                          port_config_list=port_config_list,
                          port_id=port_id,
                          lossless_flow_name=LOSSLESS_FLOW_NAME,
                          lossless_prio_list=lossless_prio_list,
                          flow_rate_percent=flow_rate_percent,
                          lossy_flow_name=LOSSY_FLOW_NAME,
                          lossy_flow_prio_list=lossy_prio_list,
                          data_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                          data_pkt_size=pkt_size,
                          prio_dscp_map=prio_dscp_map)

    """ Tgen config = testbed config + flow config """
    config = testbed_config
    config.flows = flows

    all_flow_names = [flow.name for flow in flows]

    """ Run traffic """
    flow_stats = __run_traffic(api=api,
                               config=config,
                               all_flow_names=all_flow_names,
                               exp_dur_sec=DATA_FLOW_DURATION_SEC)

    """ Verify experiment results """
    __verify_results(rows=flow_stats,
                     lossless_flow_name=LOSSLESS_FLOW_NAME,
                     lossy_flow_name=LOSSY_FLOW_NAME)


def sec_to_nanosec(x):
    return (x * 1e9)


def __gen_traffic(testbed_config,
                  port_config_list,
                  port_id,
                  lossless_flow_name,
                  lossless_prio_list,
                  flow_rate_percent,
                  lossy_flow_name,
                  lossy_flow_prio_list,
                  data_flow_dur_sec,
                  data_pkt_size,
                  prio_dscp_map):
    """
    Generate configurations of flows, including test flows, and background
    flows. Test flows and background flows are also known as data flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test
        lossless_flow_name (str): name of test flows
        lossless_prio_list (list): priorities of test flows
        flow_rate_percent (int): rate percentage for each test flow
        lossy_flow_name (str): name of background flows
        lossy_flow_prio_list (list): priorities of background flows
        data_flow_dur_sec (int): duration of data flows in second
        data_pkt_size (int): packet size of data flows in byte
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        flows configurations (list): the list should have configurations of
        len(lossless_prio_list) test flow, len(lossy_flow_prio_list) background
        flows.
    """

    result = list()

    rx_port_id = port_id
    tx_port_id_list, rx_port_id_list = select_ports(
        port_config_list=port_config_list,
        pattern="many to one",
        rx_port_id=rx_port_id)

    pytest_assert(len(tx_port_id_list) > 0, "Cannot find any TX ports")

    rx_port_config = next(
        (x for x in port_config_list if x.id == rx_port_id), None)

    """ Test flows """
    tx_port_count = 0
    n_tx_port = len(tx_port_id_list)
    n_of_lossless_prio = len(lossless_prio_list)
    for prio in lossless_prio_list + lossy_flow_prio_list:
        tx_port_id = tx_port_id_list[tx_port_count % n_tx_port]
        tx_port_config = \
            next((x for x in port_config_list if x.id == tx_port_id), None)
        tx_port_count += 1
        tx_mac = tx_port_config.mac
        if tx_port_config.gateway == rx_port_config.gateway and \
           tx_port_config.prefix_len == rx_port_config.prefix_len:
            """ If source and destination port are in the same subnet """
            rx_mac = rx_port_config.mac
        else:
            rx_mac = tx_port_config.gateway_mac

        data_endpoint = PortTxRx(
            tx_port_name=testbed_config.ports[tx_port_id].name,
            rx_port_name=testbed_config.ports[rx_port_id].name)

        eth_hdr = EthernetHeader(src=FieldPattern(tx_mac),
                                 dst=FieldPattern(rx_mac),
                                 pfc_queue=FieldPattern([prio]))

        ip_prio = Priority(
            Dscp(phb=FieldPattern(choice=prio_dscp_map[prio]),
                 ecn=FieldPattern(choice=Dscp.ECN_CAPABLE_TRANSPORT_1)))

        ipv4_hdr = Ipv4Header(src=FieldPattern(tx_port_config.ip),
                              dst=FieldPattern(rx_port_config.ip),
                              priority=ip_prio)

        lossless = prio in lossless_prio_list
        result.append(Flow(
            name='{} Prio {}'.format(
                lossless_flow_name if lossless else lossy_flow_name, prio),
            tx_rx=TxRx(data_endpoint),
            packet=[Header(choice=eth_hdr), Header(choice=ipv4_hdr)],
            size=Size(data_pkt_size),
            rate=Rate(
                'line',
                flow_rate_percent/n_of_lossless_prio
                if lossless else flow_rate_percent),
            duration=Duration(FixedSeconds(seconds=data_flow_dur_sec))))

    return result


def __run_traffic(api,
                  config,
                  all_flow_names,
                  exp_dur_sec):

    """
    Run traffic and dump per-flow statistics

    Args:
        api (obj): IXIA session
        config (obj): experiment config (testbed config + flow config)
        all_flow_names (list): list of names of all the flows
        exp_dur_sec (int): experiment duration in second

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

        """ If all the data flows have stopped """
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
    time.sleep(5)
    rows = api.get_flow_results(FlowRequest(flow_names=all_flow_names))
    api.set_state(State(FlowTransmitState(state='stop')))

    return rows


def __verify_results(rows,
                     lossless_flow_name,
                     lossy_flow_name):

    """
    Verify if we get expected experiment results

    Args:
        rows (list): per-flow statistics
        lossless_flow_name (str): name of test flows
        lossy_flow_name (str): name of background flows

    Returns:
        N/A
    """

    """ Check background flows """
    for row in rows:
        tx_frames = row['frames_tx']
        rx_frames = row['frames_rx']

        if lossy_flow_name in row['name']:
            pytest_assert(
                tx_frames != rx_frames,
                '{} should have dropped packet'.format(row['name']))
        else:
            pytest_assert(
                tx_frames == rx_frames,
                '{} should not have any dropped packet'.format(row['name']))
