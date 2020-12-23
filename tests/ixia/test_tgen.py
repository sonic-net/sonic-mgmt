import logging
import time
import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api, ixia_testbed
from tests.common.ixia.ixia_helpers import get_dut_port_id

from abstract_open_traffic_generator.flow import DeviceTxRx, TxRx, Flow, Header,\
    Size, Rate,Duration, FixedSeconds, PortTxRx, PfcPause, EthernetPause, Continuous
from abstract_open_traffic_generator.flow_ipv4 import Priority, Dscp
from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.control import State, ConfigState, FlowTransmitState
from abstract_open_traffic_generator.result import FlowRequest

@pytest.mark.topology("tgen")
@pytest.mark.disable_loganalyzer

def __gen_traffic(testbed_config,
                  dut_hostname,
                  dut_port,
                  conn_data,
                  fanout_data):

    tx_port_id = get_dut_port_id(dut_hostname=dut_hostname,
                                 dut_port=dut_port,
                                 conn_data=conn_data,
                                 fanout_data=fanout_data)

    if tx_port_id is None:
        return None

    rx_port_id = (tx_port_id + 1) % len(testbed_config.devices)

    """ Traffic configuraiton """
    flow_name = 'Test Flow'
    rate_percent = 50
    duration_sec = 2
    pkt_size = 1024

    data_endpoint = DeviceTxRx(
        tx_device_names=[testbed_config.devices[tx_port_id].name],
        rx_device_names=[testbed_config.devices[rx_port_id].name],
    )

    flow_dscp = Priority(Dscp(phb=FieldPattern(choice=[3, 4])))
    flow = Flow(
        name=flow_name,
        tx_rx=TxRx(data_endpoint),
        packet=[
            Header(choice=EthernetHeader()),
            Header(choice=Ipv4Header(priority=flow_dscp))
        ],
        size=Size(pkt_size),
        rate=Rate('line', rate_percent),
        duration=Duration(FixedSeconds(seconds=duration_sec,
                                       delay=0,
                                       delay_unit='nanoseconds'))
    )

    return [flow]


def test_tgen(conn_graph_facts,
              fanout_graph_facts,
              ixia_api,
              ixia_testbed,
              enum_dut_portname_oper_up):
    """
    Test if we can use Tgen API generate traffic in a testbed

    Args:
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        ixia_api (pytest fixture): IXIA session
        ixia_testbed (pytest fixture): L2/L3 config of a T0 testbed
        enum_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'

    Returns:
        None
    """

    words = enum_dut_portname_oper_up.split('|')
    pytest_require(len(words) == 2, "Fail to parse port name")

    dut_hostname = words[0]
    dut_port = words[1]

    config = ixia_testbed
    config.flows = __gen_traffic(testbed_config=config,
                                 dut_hostname=dut_hostname,
                                 dut_port=dut_port,
                                 conn_data=conn_graph_facts,
                                 fanout_data=fanout_graph_facts)

    flow_name = config.flows[0].name
    pkt_size = config.flows[0].size.fixed
    rate_percent = config.flows[0].rate.value
    duration_sec = config.flows[0].duration.seconds.seconds

    port_speed = config.layer1[0].speed
    words = port_speed.split('_')
    pytest_assert(len(words) == 3 and words[1].isdigit(),
                  'Fail to get port speed from {}'.format(port_speed))

    port_speed_gbps = int(words[1])

    """ Apply configuration """
    ixia_api.set_state(State(ConfigState(config=config, state='set')))

    """ Start traffic """
    ixia_api.set_state(State(FlowTransmitState(state='start')))

    """ Wait for traffic to finish """
    time.sleep(duration_sec)

    while True:
        rows = ixia_api.get_flow_results(FlowRequest(flow_names=[flow_name]))
        if len(rows) == 1 and \
           rows[0]['name'] == flow_name and \
           rows[0]['transmit'] == 'stopped':
            """ Wait for counters to fully propagate """
            time.sleep(2)
            break
        else:
            time.sleep(1)

    """ Dump per-flow statistics """
    rows = ixia_api.get_flow_results(FlowRequest(flow_names=[flow_name]))

    """ Stop traffic """
    ixia_api.set_state(State(FlowTransmitState(state='stop')))

    """ Analyze traffic results """
    pytest_assert(len(rows) == 1 and rows[0]['name'] == flow_name,
        'Fail to get results of flow {}'.format(flow_name))

    row = rows[0]
    rx_frames = row['frames_rx']
    tx_frames = row['frames_tx']

    pytest_assert(rx_frames == tx_frames,
        'Unexpected packet losses (Tx: {}, Rx: {})'.format(tx_frames, rx_frames))

    tput_bps = port_speed_gbps * 1e9 * rate_percent / 100.0
    exp_rx_frames = tput_bps * duration_sec / 8 / pkt_size

    deviation_thresh = 0.05
    ratio = float(exp_rx_frames) / rx_frames
    deviation = abs(ratio - 1)

    pytest_assert(deviation <= deviation_thresh,
        'Expected / Actual # of pkts: {} / {}'.format(exp_rx_frames, rx_frames))
