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

PAUSE_FLOW_NAME = 'Pause Storm'
TEST_FLOW_NAME = 'Test Flow'
TEST_FLOW_RATE_PERCENT = 45
BG_FLOW_NAME = 'Background Flow'
BG_FLOW_RATE_PERCENT = 45
DATA_PKT_SIZE = 1024
DATA_FLOW_DURATION_SEC = 2
DATA_FLOW_DELAY_SEC = 1
IXIA_POLL_DELAY_SEC = 2
TOLERANCE_THRESHOLD = 0.05

def run_pfc_test(api,
                 conn_data, 
                 fanout_data, 
                 duthost, 
                 port, 
                 global_pause, 
                 pause_prio_list, 
                 test_prio_list, 
                 bg_prio_list,
                 prio_dscp_map,
                 test_traffic_pause):
    
    words = port.split('|')
    pytest_require(len(words) == 2, "Fail to parse port name")
    
    dut_hostname = words[0]
    port_name = words[1]
    pytest_require(dut_hostname == duthost.hostname, "Invalid dut hostname")

    """ Disable PFC watchdog """
    duthost.shell('sudo pfcwd stop')

    config = __testbed_config__(conn_data=conn_data,
                                fanout_data=fanout_data,
                                duthost=duthost,
                                dut_port=port_name)
    
    __traffic_config__(testbed_config=config,
                       pause_flow_name=PAUSE_FLOW_NAME,
                       global_pause=global_pause, 
                       pause_prio_list=pause_prio_list,
                       test_flow_name=TEST_FLOW_NAME, 
                       test_flow_prio_list=test_prio_list,
                       test_flow_rate_percent=TEST_FLOW_RATE_PERCENT,
                       bg_flow_name=BG_FLOW_NAME,
                       bg_flow_prio_list=bg_prio_list,
                       bg_flow_rate_percent=BG_FLOW_RATE_PERCENT,
                       data_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                       data_flow_delay_sec=DATA_FLOW_DELAY_SEC,
                       data_pkt_size=DATA_PKT_SIZE,
                       prio_dscp_map=prio_dscp_map)

    """
    import json
    config_json = json.dumps(config, indent=2, default=lambda x: x.__dict__)
    print(config_json)
    """

    flow_stats = __run_traffic__(api=api,
                                 config=config,
                                 pause_flow_name=PAUSE_FLOW_NAME,
                                 test_flow_name=TEST_FLOW_NAME,
                                 bg_flow_name=BG_FLOW_NAME,
                                 exp_dur_sec=DATA_FLOW_DURATION_SEC+DATA_FLOW_DELAY_SEC)

    speed_str = config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])

    __verify_results__(rows=flow_stats,
                       pause_flow_name=PAUSE_FLOW_NAME,
                       test_flow_name=TEST_FLOW_NAME,
                       bg_flow_name=BG_FLOW_NAME,
                       data_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                       test_flow_rate_percent=TEST_FLOW_RATE_PERCENT,
                       bg_flow_rate_percent=BG_FLOW_RATE_PERCENT,
                       data_pkt_size=DATA_PKT_SIZE,
                       speed_gbps=speed_gbps,
                       test_flow_pause=test_traffic_pause,
                       tolerance=TOLERANCE_THRESHOLD)

def __testbed_config__(conn_data, fanout_data, duthost, dut_port):
    ixia_fanout = get_peer_ixia_chassis(conn_data=conn_data,
                                        dut_hostname=duthost.hostname)

    pytest_require(ixia_fanout is not None, 
                   skip_message="Cannot find the peer IXIA chassis")

    ixia_fanout_id = list(fanout_data.keys()).index(ixia_fanout)
    ixia_fanout_list = IxiaFanoutManager(fanout_data)
    ixia_fanout_list.get_fanout_device_details(device_number=ixia_fanout_id)

    ixia_ports = ixia_fanout_list.get_ports(peer_device=duthost.hostname)
    pytest_require(len(ixia_ports) >= 2, 
                   skip_message="The test requires at least two ports")

    port_id = None
    for i in range(len(ixia_ports)):
        ixia_port = ixia_ports[i]
        if ixia_port['peer_port'] == dut_port:
            port_id = i
            break
    
    pytest_require(port_id is not None, 
                   skip_message="Cannot find the correspoinding IXIA port")
    
    rx_id = port_id 
    tx_id = (port_id + 1) % len(ixia_ports)

    rx_port_location = get_tgen_location(ixia_ports[rx_id])
    tx_port_location = get_tgen_location(ixia_ports[tx_id])

    rx_port_speed = int(ixia_ports[rx_id]['speed'])
    tx_port_speed = int(ixia_ports[tx_id]['speed'])
    pytest_require(rx_port_speed==tx_port_speed, 
                   skip_message="Two ports should have the same speed")

    """ L1 configuration """
    rx_port = Port(name='Rx Port', location=rx_port_location)
    tx_port = Port(name='Tx Port', location=tx_port_location)

    pfc = Ieee8021qbb(pfc_delay=0,
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

sec_to_nanosec = lambda x : x * 1e9

def __class_enable_vector__(prio_list):
    vector = 0

    for p in prio_list:
        vector += (2**p)
     
    return "{:x}".format(vector)

def __traffic_config__(testbed_config,
                       pause_flow_name,
                       global_pause, 
                       pause_prio_list,
                       test_flow_name, 
                       test_flow_prio_list,
                       test_flow_rate_percent,
                       bg_flow_name,
                       bg_flow_prio_list,
                       bg_flow_rate_percent,
                       data_flow_dur_sec,
                       data_flow_delay_sec,
                       data_pkt_size,
                       prio_dscp_map):

    config = testbed_config

    data_endpoint = DeviceTxRx(
        tx_device_names=[config.devices[0].name],
        rx_device_names=[config.devices[1].name],
    )

    data_flow_delay_nanosec = sec_to_nanosec(data_flow_delay_sec)
        
    """ Test flow """
    test_flow_dscp_list = []
    for prio in test_flow_prio_list:
        test_flow_dscp_list += prio_dscp_map[prio]

    test_flow_dscp = Priority(Dscp(phb=FieldPattern(choice=test_flow_dscp_list)))
    test_flow_pfc_queue = FieldPattern([test_flow_prio_list[0]])

    test_flow = Flow(
        name=test_flow_name,
        tx_rx=TxRx(data_endpoint),
        packet=[
            Header(choice=EthernetHeader(pfc_queue=test_flow_pfc_queue)),
            Header(choice=Ipv4Header(priority=test_flow_dscp))
        ],
        size=Size(data_pkt_size),
        rate=Rate('line', test_flow_rate_percent),
        duration=Duration(FixedSeconds(seconds=data_flow_dur_sec, 
                                       delay=data_flow_delay_nanosec, 
                                       delay_unit='nanoseconds'))
    )

    """ Background flow """
    bg_flow_dscp_list = []
    for prio in bg_flow_prio_list:
        bg_flow_dscp_list += prio_dscp_map[prio]

    bg_flow_dscp = Priority(Dscp(phb=FieldPattern(choice=bg_flow_dscp_list)))
    bg_flow_pfc_queue = FieldPattern([bg_flow_prio_list[0]])

    bg_flow = Flow(
        name=bg_flow_name,
        tx_rx=TxRx(data_endpoint),
        packet=[
            Header(choice=EthernetHeader(pfc_queue=bg_flow_pfc_queue)),
            Header(choice=Ipv4Header(priority=bg_flow_dscp))
        ],
        size=Size(data_pkt_size),
        rate=Rate('line', bg_flow_rate_percent),
        duration=Duration(FixedSeconds(seconds=data_flow_dur_sec, 
                                       delay=data_flow_delay_nanosec, 
                                       delay_unit='nanoseconds'))
    )

    """ Pause storm """                 
    if global_pause:
        pause_pkt = Header(EthernetPause(
            dst=FieldPattern(choice='01:80:C2:00:00:01'),
            src=FieldPattern(choice='00:00:fa:ce:fa:ce')
        ))

    else:
        pause_time = []
        for x in range(8):
            if x in pause_prio_list:
                pause_time.append('ffff')
            else:
                pause_time.append('0000')
        
        vector = __class_enable_vector__(pause_prio_list)

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

    pause_src_point = PortTxRx(tx_port_name=config.ports[1].name, 
                               rx_port_name=config.ports[1].name)
    pause_flow = Flow(
        name=pause_flow_name,
        tx_rx=TxRx(pause_src_point),
        packet=[pause_pkt],
        size=Size(64),
        rate=Rate('line', value=100),
        duration=Duration(Continuous(delay=0, delay_unit='nanoseconds'))
    )

    """ Add all the flows to the configuration """
    config.flows.append(test_flow)
    config.flows.append(bg_flow)
    config.flows.append(pause_flow)

def __run_traffic__(api, 
                    config, 
                    pause_flow_name, 
                    test_flow_name, 
                    bg_flow_name,
                    exp_dur_sec):

    api.set_state(State(ConfigState(config=config, state='set')))
    
    api.set_state(State(FlowTransmitState(state='start')))
    
    time.sleep(exp_dur_sec)

    while True:
        rows = api.get_flow_results(FlowRequest(flow_names=[test_flow_name, 
                                                            bg_flow_name]))
        
        """ If both data flows have stopped """
        transmit_states = [row['transmit'] for row in rows]
        if len(rows) == 2 and list(set(transmit_states)) == ['stopped']:
            time.sleep(IXIA_POLL_DELAY_SEC)
            break 
        else:
            time.sleep(1)

    """ Dump per-flow statistics """
    rows = api.get_flow_results(FlowRequest(flow_names=[test_flow_name, 
                                                        bg_flow_name, 
                                                        pause_flow_name]))
    
    api.set_state(State(FlowTransmitState(state='stop')))
    time.sleep(3600)
    return rows

def __verify_results__(rows, 
                       pause_flow_name, 
                       test_flow_name, 
                       bg_flow_name,
                       data_flow_dur_sec,
                       test_flow_rate_percent,
                       bg_flow_rate_percent,
                       data_pkt_size,
                       speed_gbps,
                       test_flow_pause,
                       tolerance):


    """ All the pause frames should be dropped """
    pause_flow_row = next(row for row in rows if row["name"] == pause_flow_name)
    tx_frames = pause_flow_row['frames_tx']
    rx_frames = pause_flow_row['frames_rx']
    pytest_assert(tx_frames > 0 and rx_frames == 0,
                  'All the pause frames should be dropped')
    
    """ Check background flow """
    bg_flow_row = next(row for row in rows if row["name"] == bg_flow_name) 
    tx_frames = bg_flow_row['frames_tx']
    rx_frames = bg_flow_row['frames_rx']

    pytest_assert(tx_frames == rx_frames, 
                  '{} should not have any dropped packet'.format(bg_flow_name))

    exp_bg_flow_rx_pkts =  bg_flow_rate_percent / 100.0 * speed_gbps \
            * 1e9 * data_flow_dur_sec / 8.0 / data_pkt_size
    deviation = (rx_frames - exp_bg_flow_rx_pkts) / float(exp_bg_flow_rx_pkts)
    pytest_assert(deviation < tolerance,
                  '{} should receive {} packets (actual {})'.\
                  format(bg_flow_name, exp_bg_flow_rx_pkts, rx_frames))
    
    """ Check test flow """
    test_flow_row = next(row for row in rows if row["name"] == test_flow_name) 
    tx_frames = test_flow_row['frames_tx']
    rx_frames = test_flow_row['frames_rx']

    if test_flow_pause:
        pytest_assert(tx_frames > 0 and rx_frames == 0, 
                      '{} should be paused'.format(test_flow_name))
    else:
        pytest_assert(tx_frames == rx_frames, 
                      '{} should not have any dropped packet'.format(test_flow_name))

        exp_test_flow_rx_pkts = test_flow_rate_percent / 100.0 * speed_gbps \
            * 1e9 * data_flow_dur_sec / 8.0 / data_pkt_size
        deviation = (rx_frames - exp_test_flow_rx_pkts) / float(exp_test_flow_rx_pkts)
        pytest_assert(deviation < tolerance,
                      '{} should receive {} packets (actual {})'.\
                      format(test_flow_name, exp_test_flow_rx_pkts, rx_frames))
