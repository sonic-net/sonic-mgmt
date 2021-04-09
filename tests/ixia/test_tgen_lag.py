import logging
import time
import pytest
import random
from datetime import datetime

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api, ixia_testbed_config
from tests.common.ixia.ixia_helpers import IxiaFanoutManager, get_tgen_location,\
    get_dut_port_id

from tests.common.ixia.port import IxiaPortConfig, IxiaPortType, select_ports

from abstract_open_traffic_generator.port import Port
from abstract_open_traffic_generator.config import Options, Config
from abstract_open_traffic_generator.layer1 import Layer1, FlowControl,\
    Ieee8021qbb, AutoNegotiation
import abstract_open_traffic_generator.lag as lag

from abstract_open_traffic_generator.device import Device, Ethernet, Ipv4,\
    Pattern
from ixnetwork_open_traffic_generator.ixnetworkapi import IxNetworkApi
from abstract_open_traffic_generator.port import Options as PortOptions

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

def gen_traffic(testbed_config, duthost, tx_port_config_list, rx_port_config_list):
    flows = []
    rate_percent = 90 / len(tx_port_config_list) / len(rx_port_config_list)
    duration_sec = 2
    pkt_size = 1024

    for tx_port_config in tx_port_config_list:
        for rx_port_config in rx_port_config_list:
            src_id = tx_port_config.id
            dst_id = rx_port_config.id

            if src_id == dst_id:
                continue

            src_ip = tx_port_config.ip
            dst_ip = rx_port_config.ip

            src_mac = tx_port_config.mac
            if tx_port_config.gateway == rx_port_config.gateway and \
               tx_port_config.prefix_len == rx_port_config.prefix_len:
                """ If soruce and destination port are in the same subnet """
                dst_mac = rx_port_config.mac
            else:
                dst_mac = tx_port_config.gateway_mac

            flow_name = 'Test Flow {} -> {}'.format(src_id, dst_id)

            endpoint = PortTxRx(tx_port_name=testbed_config.ports[src_id].name,
                                rx_port_name=testbed_config.ports[dst_id].name)

            eth_hdr = EthernetHeader(src=FieldPattern(src_mac),
                                     dst=FieldPattern(dst_mac))

            flow_dscp = Priority(Dscp(phb=FieldPattern(choice=[3])))
            ipv4_hdr = Ipv4Header(src=FieldPattern(src_ip),
                                  dst=FieldPattern(dst_ip),
                                  priority=flow_dscp)

            flow = Flow(
                name=flow_name,
                tx_rx=TxRx(endpoint),
                packet=[Header(choice=eth_hdr), Header(choice=ipv4_hdr)],
                size=Size(pkt_size),
                rate=Rate('line', rate_percent),
                duration=Duration(FixedSeconds(seconds=duration_sec))
            )
            flows.append(flow)

    return flows

def run_traffic(api, config):
    flow_names = [flow.name for flow in config.flows]
    pkt_size = config.flows[0].size.fixed
    rate_percent = config.flows[0].rate.value
    duration_sec = config.flows[0].duration.seconds.seconds

    port_speed = config.layer1[0].speed
    words = port_speed.split('_')
    pytest_assert(len(words) == 3 and words[1].isdigit(),
                  'Fail to get port speed from {}'.format(port_speed))
    speed_gbps = int(words[1])

    api.set_state(State(ConfigState(config=config, state='set')))

    api.set_state(State(FlowTransmitState(state='start')))

    time.sleep(duration_sec + 1)

    attempts = 0
    max_attempts = 20

    while attempts < max_attempts:
        rows = api.get_flow_results(FlowRequest(flow_names=flow_names))
        transmit_states = [row['transmit'] for row in rows]
        if len(rows) == len(flow_names) and\
           list(set(transmit_states)) == ['stopped']:
            time.sleep(1)
            break
        else:
            time.sleep(1)
            attempts += 1

    pytest_assert(attempts < max_attempts,
                  "Flows do not stop in {} seconds".format(max_attempts))

    rows = api.get_flow_results(FlowRequest(flow_names=flow_names))
    api.set_state(State(FlowTransmitState(state='stop')))

    tolerance = 0.05

    for row in rows:
        tx_frames = row['frames_tx']
        rx_frames = row['frames_rx']
        flow_name = row['name']

        pytest_assert(tx_frames == rx_frames,
                      '{} should not have any dropped packet'.format(flow_name))

        exp_rx_pkts =  rate_percent / 100.0 * speed_gbps * 1e9 * duration_sec / 8.0 / pkt_size
        deviation = (rx_frames - exp_rx_pkts) / float(exp_rx_pkts)

        pytest_assert(abs(deviation) < tolerance,
                      '{} should receive {} packets (actual {})'.\
                      format(flow_name, exp_rx_pkts, rx_frames))

def test_tgen_lag(ixia_api,
                  ixia_testbed_config,
                  duthosts,
                  rand_one_dut_hostname):

    duthost = duthosts[rand_one_dut_hostname]
    config, port_config_list = ixia_testbed_config

    pc_port_config_list  = [x for x in port_config_list \
                            if x.type == IxiaPortType.PortChannelMember]

    pytest_require(len(pc_port_config_list) > 0)

    for pc_port_config in pc_port_config_list:
        """ Use each portchannel interface as the receiver """
        tx_port_id_list, rx_port_id_list = select_ports(port_config_list=port_config_list,
                                                        duthost=duthost,
                                                        pattern="many to one",
                                                        rx_port_id=pc_port_config.id)

        tx_port_config_list = [x for x in port_config_list if x.id in tx_port_id_list]
        rx_port_config_list = [x for x in port_config_list if x.id in rx_port_id_list]

        config.flows = gen_traffic(testbed_config=config,
                                   duthost=duthost,
                                   tx_port_config_list=tx_port_config_list,
                                   rx_port_config_list=rx_port_config_list)

        run_traffic(api=ixia_api, config=config)
