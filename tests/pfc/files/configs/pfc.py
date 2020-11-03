import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import logger
from tests.common.helpers.assertions import pytest_assert
from tests.common.ixia.ixia_helpers import IxiaFanoutManager, get_location
from tests.common.tgen.tgen_helpers import *

from tests.common.ixia.common_helpers import get_vlan_subnet, \
    get_addrs_in_subnet

###############################################################################
# Imports for Tgen and IxNetwork abstract class
###############################################################################
from abstract_open_traffic_generator.port import Port
from abstract_open_traffic_generator.config import Options Config
#from abstract_open_traffic_generator.config import Config

from abstract_open_traffic_generator.result import FlowRequest
from abstract_open_traffic_generator.control import *

from abstract_open_traffic_generator.device import Device, Ethernet, Ipv4,\
    Pattern

from abstract_open_traffic_generator.flow import DeviceTxRx, TxRx, Flow,\
    Header, Size, Rate, Duration, FixedSeconds, PortTxRx, PfcPause,\
    EthernetPause, Continuous

from abstract_open_traffic_generator.flow_ipv4 import Priority, Dscp

from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.port import Options as PortOptions


def __calculate_priority_vector__(v) :
    """
    This function calculates the priority vector field of PFC Pause packets.

    Args:
        v (list of string) : This is a list of 8 items and indicates pause 
            class values. It's format is ['0', 'ffff', '0', '0', '0', '0', '0'], 
            where 'ffff' indicates that pause class is enabled for that index.

    Returns:
        Value of priority vector in hex format 
    """
    s = 0
    for i in range(8)  :
        if v[i] != '0' :
           s += 2**i
    return "%x"%(s)


sec_to_nano_sec = lambda x : x * 1000000000.0
def __base_configs__(duthost,
                     lossless_prio_dscp_map,
                     l1_config,
                     start_delay_secs,
                     traffic_duration,
                     pause_line_rate,
                     traffic_line_rate,
                     pause_frame_type,
                     frame_size,
                     test_flow_name,
                     background_flow_name): 

    lossless_prio_list = [str(prio) for prio in lossless_prio_dscp_map]
    lossy_prio_list = [str(x) for x in range(64) if str(x) not in lossless_prio_list]

    tx = l1_config.ports[0]
    rx = l1_config.ports[1]

    vlan_subnet = get_vlan_subnet(duthost)
    pytest_assert(vlan_subnet is not None,
                  "Fail to get Vlan subnet information")

    vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, 2)

    gw_addr = vlan_subnet.split('/')[0]
    prefix = vlan_subnet.split('/')[1]
    tx_port_ip = vlan_ip_addrs[1]
    rx_port_ip = vlan_ip_addrs[0]

    tx_gateway_ip = gw_addr
    rx_gateway_ip = gw_addr

    test_line_rate = traffic_line_rate
    background_line_rate = traffic_line_rate

    pytest_assert(test_line_rate + background_line_rate <= 100,
        "test_line_rate + background_line_rate should be less than 100")

    ######################################################################
    # Create TX stack configuration
    ######################################################################
    tx_ipv4 = Ipv4(name='Tx Ipv4',
                   address=Pattern(tx_port_ip),
                   prefix=Pattern(prefix),
                   gateway=Pattern(tx_gateway_ip),
                   ethernet=Ethernet(name='Tx Ethernet'))

    tx_device = Device(container_name=tx.name,
                       name='Tx Device', 
                       device_count=1,
                       choice=tx_ipv4)
    l1_config.devices.append(tx_device) 
    ######################################################################
    # Create RX stack configuration
    ######################################################################
    rx_ipv4 = Ipv4(name='Rx Ipv4',
                   address=Pattern(rx_port_ip),
                   prefix=Pattern(prefix),
                   gateway=Pattern(rx_gateway_ip),
                   ethernet=Ethernet(name='Rx Ethernet'))

    rx_device = Device(container_name=rx.name,
                       name='Rx Device',
                       device_count=1,
                       choice=rx_ipv4)
    l1_config.devices.append(rx_device)


    data_endpoint = DeviceTxRx(
        tx_device_names=[tx_device.name],
        rx_device_names=[rx_device.name],
    )
    delay_nano_sec = sec_to_nano_sec(start_delay_secs)
    ######################################################################
    # Traffic configuration Test data
    ######################################################################
    test_dscp = Priority(Dscp(phb=FieldPattern(choice=lossy_prio_list)))
    test_flow = Flow(
        name=test_flow_name,
        tx_rx=TxRx(data_endpoint),
        packet=[
            Header(choice=EthernetHeader()),
            Header(choice=Ipv4Header(priority=test_dscp))
        ],
        size=Size(frame_size),
        rate=Rate('line', test_line_rate),
        duration=Duration(FixedSeconds(seconds=traffic_duration, delay=delay_nano_sec, delay_unit='nanoseconds'))
    )

    l1_config.flows.append(test_flow)
    #######################################################################
    # Traffic configuration Background data
    #######################################################################
    background_dscp = Priority(Dscp(phb=FieldPattern(choice=lossless_prio_list)))
    background_flow = Flow(
        name=background_flow_name,
        tx_rx=TxRx(data_endpoint),
        packet=[
            Header(choice=EthernetHeader()),
            Header(choice=Ipv4Header(priority=background_dscp))
        ],
        size=Size(frame_size),
        rate=Rate('line', background_line_rate),
        duration=Duration(FixedSeconds(seconds=traffic_duration, delay=delay_nano_sec, delay_unit='nanoseconds'))
    )
    l1_config.flows.append(background_flow)

    #######################################################################
    # Traffic configuration Pause
    #######################################################################
    pause_src_point = PortTxRx(tx_port_name='Rx', rx_port_names=['Rx'])
    if (pause_frame_type == 'priority') :
        p = ['0' if str(x) in lossless_prio_list else 'ffff' for x in range(8)]
        
        v = __calculate_priority_vector__(p) 
        pause = Header(PfcPause(
            dst=FieldPattern(choice='01:80:C2:00:00:01'),
            src=FieldPattern(choice='00:00:fa:ce:fa:ce'),
            class_enable_vector=FieldPattern(choice=v),
            pause_class_0=FieldPattern(choice=p[0]),
            pause_class_1=FieldPattern(choice=p[1]),
            pause_class_2=FieldPattern(choice=p[2]),
            pause_class_3=FieldPattern(choice=p[3]),
            pause_class_4=FieldPattern(choice=p[4]),
            pause_class_5=FieldPattern(choice=p[5]),
            pause_class_6=FieldPattern(choice=p[6]),
            pause_class_7=FieldPattern(choice=p[7]),
        ))

        pause_flow = Flow(
            name='Pause Storm',
            tx_rx=TxRx(pause_src_point),
            packet=[pause],
            size=Size(64),
            rate=Rate('line', value=100),
            duration=Duration(Continuous(delay=0, delay_unit='nanoseconds'))
        )
    elif (pause_frame_type == 'global') :
        pause = Header(EthernetPause(
        dst=FieldPattern(choice='01:80:C2:00:00:01'),
            src=FieldPattern(choice='00:00:fa:ce:fa:ce')
        ))

        pause_flow = Flow(
            name='Pause Storm',
            tx_rx=TxRx(pause_src_point),
            packet=[pause],
            size=Size(64),
            rate=Rate('line', value=pause_line_rate),
            duration=Duration(Continuous(delay=0, delay_unit='nanoseconds'))
        )
    else :
        pass   

    l1_config.flows.append(pause_flow)
    return l1_config


def __port_bandwidth__(conn_graph_facts,
                       fanout_graph_facts,
                       bw_multiplier) :
   """
   This fixture extracts the ixia port bandwidth from fanout_graph_facts,
   and verifies it with the port speed of the DUT. The speed of all the 
   ixia ports and dut port must be same. 

   Args:
      conn_graph_facts (fixture): connection graph fact.
      fanout_graph_facts (fixture): fanout graph facts
      bw_multiplier (int): multiplier to convert the port speed into bandwidth in 
         bps unit, its value is 1000000.

   Returns:
      Port bandwidth in bps unit.
   """  
   fanout_devices = IxiaFanoutManager(fanout_graph_facts)
   fanout_devices.get_fanout_device_details(device_number=0)
   device_conn = conn_graph_facts['device_conn']
   available_phy_port = fanout_devices.get_ports()
   reference_peer = available_phy_port[0]['peer_port']
   reference_speed = int(device_conn[reference_peer]['speed'])

   for intf in available_phy_port:
        peer_port = intf['peer_port']
        intf['speed'] = int(device_conn[peer_port]['speed'])
        pytest_assert(intf['speed'] == reference_speed,
            "speed of all the ports are not same")

   return reference_speed * bw_multiplier


def run_test_pfc_lossy(api,
                       duthost,
                       conn_graph_facts,
                       fanout_graph_facts,
                       port_id,
                       lossless_prio,
                       start_delay_secs,
                       pause_line_rate,
                       traffic_line_rate,
                       traffic_duration,
                       pause_frame_type,
                       frame_size,
                       test_flow_name,
                       background_flow_name,
                       bw_multiplier,
                       tolerance_threshold):

    tgen_ports = TgenPorts(conn_graph_facts, fanout_graph_facts) 
    port_list = tgen_ports.create_ports_list(2, port_id)
    l1_config = tgen_ports.l1_config(port_list)

    l1_config.layer1[0].port_names = ['Tx', 'Rx']
    l1_config.ports[0].name = 'Tx'
    l1_config.ports[1].name = 'Rx'

    duthost.shell('sudo pfcwd stop')

    base_config = __base_configs__(duthost,
                                   lossless_prio,
                                   l1_config,
                                   start_delay_secs,
                                   traffic_duration,
                                   pause_line_rate,
                                   traffic_line_rate,
                                   pause_frame_type,
                                   frame_size,
                                   test_flow_name,
                                   background_flow_name)

    api.set_state(State(ConfigState(config=base_config, state='set')))

    # start all flows
    api.set_state(State(FlowTransmitState(state='start')))

    exp_dur = start_delay_secs + traffic_duration
    logger.info("Traffic is running for %s seconds" %(exp_dur))
    time.sleep(exp_dur)

    # stop all flows
    api.set_state(State(FlowTransmitState(state='stop')))

    port_bandwidth_value = __port_bandwidth__(conn_graph_facts,
                                              fanout_graph_facts,
                                              bw_multiplier)

    stat_captions =[test_flow_name, background_flow_name]
    for row in api.get_flow_results(FlowRequest(flow_names=stat_captions)):
        if (row['name'] == test_flow_name) or (row['name'] == background_flow_name):
            if ((row['frames_rx'] == 0) or (row['frames_tx'] != row['frames_rx'])):
                 pytest.fail("Not all %s reached Rx End" %(row['name']))

            line_rate = traffic_line_rate / 100.0
            exp_rx_bytes = (port_bandwidth_value * line_rate * traffic_duration) / 8
            tolerance_ratio = row['bytes_rx'] / exp_rx_bytes

            if ((tolerance_ratio < tolerance_threshold) or
                (tolerance_ratio > 1)) :
                pytest.fail("expected % of packets not received at the RX port")


