import logging
import time
import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api
from tests.common.ixia.ixia_helpers import IxiaFanoutManager, get_tgen_location
from tests.common.ixia.common_helpers import get_vlan_subnet, get_addrs_in_subnet,\
    get_peer_ixia_chassis

from abstract_open_traffic_generator.port import Port
from abstract_open_traffic_generator.config import Options, Config
from abstract_open_traffic_generator.layer1 import Layer1, FlowControl, Ieee8021qbb,\
    AutoNegotiation

from abstract_open_traffic_generator.device import Device, Ethernet, Ipv4, Pattern
from abstract_open_traffic_generator.flow import DeviceTxRx, TxRx, Flow, Header,\
    Size, Rate,Duration, FixedSeconds, PortTxRx, PfcPause, EthernetPause, Continuous
from abstract_open_traffic_generator.flow_ipv4 import Priority, Dscp
from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.port import Options as PortOptions
from abstract_open_traffic_generator.control import State, ConfigState, FlowTransmitState
from abstract_open_traffic_generator.result import FlowRequest

@pytest.mark.topology("tgen")
@pytest.mark.disable_loganalyzer

@pytest.fixture(scope = "function")
def testbed_config(conn_graph_facts, fanout_graph_facts, duthost):
    ixia_fanout = get_peer_ixia_chassis(conn_data=conn_graph_facts,
                                        dut_hostname=duthost.hostname)

    pytest_require(ixia_fanout is not None, 
                   skip_message="Cannot find the peer IXIA chassis")

    ixia_fanout_id = list(fanout_graph_facts.keys()).index(ixia_fanout)
    ixia_fanout_list = IxiaFanoutManager(fanout_graph_facts)
    ixia_fanout_list.get_fanout_device_details(device_number=ixia_fanout_id)


    ixia_ports = ixia_fanout_list.get_ports(peer_device=duthost.hostname)
    pytest_require(len(ixia_ports) >= 2, 
                   skip_message="The test requires at least two ports")

    rx_id = 0
    tx_id = 1

    rx_port_location = get_tgen_location(ixia_ports[rx_id])
    tx_port_location = get_tgen_location(ixia_ports[tx_id])

    rx_port_speed = int(ixia_ports[rx_id]['speed'])
    tx_port_speed = int(ixia_ports[tx_id]['speed'])
    pytest_require(rx_port_speed==tx_port_speed, 
                   skip_message="Two ports should have the same speed")

    """ L1 configuration """
    rx_port = Port(name='Rx Port', location=rx_port_location)
    tx_port = Port(name='Tx Port', location=tx_port_location)

    pfc = Ieee8021qbb(pfc_delay=1,
                      pfc_class_0=0,
                      pfc_class_1=1,
                      pfc_class_2=2,
                      pfc_class_3=3,
                      pfc_class_4=4,
                      pfc_class_5=5,
                      pfc_class_6=6,
                      pfc_class_7=7)

    flow_ctl = FlowControl(choice=pfc)

    auto_negotiation = AutoNegotiation(link_training=True,
                                       rs_fec=True)

    l1_config = Layer1(name='L1 config',
                       speed='speed_%d_gbps' % (rx_port_speed/1000),
                       auto_negotiate=False,
                       auto_negotiation=auto_negotiation,
                       flow_control=flow_ctl,
                       port_names=[tx_port.name, rx_port.name])

    config = Config(ports=[tx_port, rx_port],
                    layer1=[l1_config],
                    options=Options(PortOptions(location_preemption=True)))
    
    vlan_subnet = get_vlan_subnet(duthost)
    pytest_assert(vlan_subnet is not None,
                  "Fail to get Vlan subnet information")

    vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, 2)
    gw_addr = vlan_subnet.split('/')[0]
    prefix = vlan_subnet.split('/')[1]
    tx_port_ip = vlan_ip_addrs[0]
    rx_port_ip = vlan_ip_addrs[1]
    tx_gateway_ip = gw_addr
    rx_gateway_ip = gw_addr

    """ L2/L3 configuration """
    tx_ipv4 = Ipv4(name='Tx Ipv4',
                   address=Pattern(tx_port_ip),
                   prefix=Pattern(prefix),
                   gateway=Pattern(tx_gateway_ip),
                   ethernet=Ethernet(name='Tx Ethernet'))

    config.devices.append(Device(name='Tx Device',
                                 device_count=1,
                                 container_name=tx_port.name,
                                 choice=tx_ipv4))
    
    rx_ipv4 = Ipv4(name='Rx Ipv4',
                   address=Pattern(rx_port_ip),
                   prefix=Pattern(prefix),
                   gateway=Pattern(rx_gateway_ip),
                   ethernet=Ethernet(name='Rx Ethernet'))

    config.devices.append(Device(name='Rx Device',
                                 device_count=1,
                                 container_name=rx_port.name,
                                 choice=rx_ipv4))
    
    return config 

@pytest.fixture(scope = "function")
def traffic_config(testbed_config):
    config = testbed_config 

    """ Traffic configuraiton """
    flow_name = 'Test Flow'
    rate_percent = 50
    duration_sec = 2
    pkt_size = 1024 

    data_endpoint = DeviceTxRx(
        tx_device_names=[config.devices[0].name],
        rx_device_names=[config.devices[1].name],
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

    config.flows = [flow]
    return config

def test_tgen(traffic_config, ixia_api):
    config = traffic_config

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

