import time
import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts                                                                      # noqa F401
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api, ixia_testbed_config                 # noqa F401
from tests.common.ixia.port import select_ports
from tests.common.ixia.qos_fixtures import prio_dscp_map                                    # noqa F401

from abstract_open_traffic_generator.flow import DeviceTxRx, TxRx, Flow, Header,\
    Size, Rate, Duration, FixedSeconds, PortTxRx, PfcPause, EthernetPause, Continuous       # noqa F401
from abstract_open_traffic_generator.flow_ipv4 import Priority, Dscp
from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.control import State, ConfigState, FlowTransmitState
from abstract_open_traffic_generator.result import FlowRequest


pytestmark = [
    pytest.mark.topology('tgen'),
    pytest.mark.disable_loganalyzer
]


def __gen_all_to_all_traffic(testbed_config,
                             port_config_list,
                             dut_hostname,
                             conn_data,
                             fanout_data,
                             priority,
                             prio_dscp_map):            # noqa F811

    flows = []

    rate_percent = 100 / (len(port_config_list) - 1)
    duration_sec = 2
    pkt_size = 1024

    tx_port_id_list, rx_port_id_list = select_ports(port_config_list=port_config_list,
                                                    pattern="all to all",
                                                    rx_port_id=0)

    for tx_port_id in tx_port_id_list:
        for rx_port_id in rx_port_id_list:
            if tx_port_id == rx_port_id:
                continue

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

            eth_hdr = EthernetHeader(src=FieldPattern(tx_mac),
                                     dst=FieldPattern(rx_mac),
                                     pfc_queue=FieldPattern([priority]))

            ip_prio = Priority(Dscp(phb=FieldPattern(choice=prio_dscp_map[priority]),
                                    ecn=FieldPattern(choice=Dscp.ECN_CAPABLE_TRANSPORT_1)))
            ipv4_hdr = Ipv4Header(src=FieldPattern(tx_port_config.ip),
                                  dst=FieldPattern(rx_port_config.ip),
                                  priority=ip_prio)

            flow_name = "Flow {} -> {}".format(tx_port_id, rx_port_id)
            flow = Flow(
                name=flow_name,
                tx_rx=TxRx(data_endpoint),
                packet=[Header(choice=eth_hdr), Header(choice=ipv4_hdr)],
                size=Size(pkt_size),
                rate=Rate('line', rate_percent),
                duration=Duration(FixedSeconds(seconds=duration_sec))
            )

            flows.append(flow)

    return flows


def test_tgen(ixia_api, ixia_testbed_config, conn_graph_facts, fanout_graph_facts,      # noqa F811
              rand_one_dut_lossless_prio, prio_dscp_map):                               # noqa F811
    """
    Test if we can use Tgen API generate traffic in a testbed

    Args:
        ixia_api (pytest fixture): IXIA session
        ixia_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        rand_one_dut_lossless_prio (str): name of lossless priority to test
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)

    Returns:
        N/A
    """

    testbed_config, port_config_list = ixia_testbed_config
    dut_hostname, lossless_prio = rand_one_dut_lossless_prio.split('|')

    pytest_require(len(port_config_list) >= 2, "This test requires at least 2 ports")

    config = testbed_config
    config.flows = __gen_all_to_all_traffic(testbed_config=testbed_config,
                                            port_config_list=port_config_list,
                                            dut_hostname=dut_hostname,
                                            conn_data=conn_graph_facts,
                                            fanout_data=fanout_graph_facts,
                                            priority=int(lossless_prio),
                                            prio_dscp_map=prio_dscp_map)

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

    attempts = 0
    max_attempts = 20
    all_flow_names = [flow.name for flow in config.flows]

    while attempts < max_attempts:
        rows = ixia_api.get_flow_results(FlowRequest(flow_names=all_flow_names))

        """ If all the data flows have stopped """
        transmit_states = [row['transmit'] for row in rows]
        if len(rows) == len(all_flow_names) and\
           list(set(transmit_states)) == ['stopped']:
            time.sleep(2)
            break
        else:
            time.sleep(1)
            attempts += 1

    pytest_assert(attempts < max_attempts,
                  "Flows do not stop in {} seconds".format(max_attempts))

    """ Dump per-flow statistics """
    rows = ixia_api.get_flow_results(FlowRequest(flow_names=all_flow_names))
    ixia_api.set_state(State(FlowTransmitState(state='stop')))

    """ Analyze traffic results """
    for row in rows:
        flow_name = row['name']
        rx_frames = row['frames_rx']
        tx_frames = row['frames_tx']

        pytest_assert(rx_frames == tx_frames,
                      'packet losses for {} (Tx: {}, Rx: {})'.
                      format(flow_name, tx_frames, rx_frames))

        tput_bps = port_speed_gbps * 1e9 * rate_percent / 100.0
        exp_rx_frames = tput_bps * duration_sec / 8 / pkt_size

        deviation_thresh = 0.05
        ratio = float(exp_rx_frames) / rx_frames
        deviation = abs(ratio - 1)

        pytest_assert(deviation <= deviation_thresh,
                      'Expected / Actual # of pkts for flow {}: {} / {}'.
                      format(flow_name, exp_rx_frames, rx_frames))
