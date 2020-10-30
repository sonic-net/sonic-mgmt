import time
import datetime
import pytest
import logging

from tests.common.tgen.tgen_helpers import *
from abstract_open_traffic_generator.port import Port
from abstract_open_traffic_generator.config import Options
from abstract_open_traffic_generator.config import Config
from abstract_open_traffic_generator.layer1 import\
    Layer1, OneHundredGbe, FlowControl, Ieee8021qbb
from abstract_open_traffic_generator.layer1 import \
    Ethernet as EthernetPort
from abstract_open_traffic_generator.device import *
from abstract_open_traffic_generator.flow import \
    Flow, TxRx, DeviceTxRx, PortTxRx, Header, Size, Rate, Duration, \
    Continuous, PfcPause
from abstract_open_traffic_generator.flow_ipv4 import\
    Priority, Dscp
from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.port import Options as PortOptions
from abstract_open_traffic_generator.result import FlowRequest
from abstract_open_traffic_generator.control import *
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

""" Start delay in seconds """
START_DELAY = 1

""" Rate percentage of traffic """
TRAFFIC_LINE_RATE = 50

""" Rate percentage of Pause Traffic """
PAUSE_LINE_RATE = 50 

""" Frame size in bytes """
FRAME_SIZE = 1024

""" Time to start Pause Storm"""
T_START_PAUSE = 5

""" Time to stop Pause Storm """
T_STOP_PAUSE = 20

""" Time to stop Pause Storm """
T_STOP_TRAFFIC = 40

""" Storm Detection time """
STORM_DETECTION_TIME = 400

""" Storm Restoration time """
STORM_RESTORATION_TIME = 2000

""" Tolerance Percent """
TOLERANCE_PERCENT = 1


# pfcwd two senders two receivers
def run_basic_pfcwd_two_senders_two_receivers_test(api,
                                                   port_id,
                                                   prio,
                                                   duthost,
                                                   conn_graph_facts,
                                                   fanout_graph_facts):

    """
    PFCWD two senders and two receivers test 

    @param api: open tgen api fixture
    @param port_id: starting index of port_id from topo file 
    @param prio: dscp priority
    @param duthost: Sonic DUT duthost fixture
    @param conn_graph_facts: conn_graph_facts fixture to get testbed connection information
    @param fanout_graph_facts: fanout_graph_facts fixture to get testbed connection information
    """

    __create_tgen_config_two_senders_two_receivers__(api=api,
                                                     port_id=port_id,
                                                     prio=prio,
                                                     duthost=duthost,
                                                     conn_graph_facts=conn_graph_facts,
                                                     fanout_graph_facts=fanout_graph_facts,
                                                     traffic_line_rate=TRAFFIC_LINE_RATE,
                                                     start_delay=START_DELAY,
                                                     pause_line_rate=PAUSE_LINE_RATE,
                                                     frame_size=FRAME_SIZE,
                                                     t_start_pause=T_START_PAUSE)

    __pfcwd_two_senders_two_receivers_test__(api=api,
                                             duthost=duthost,
                                             start_delay=START_DELAY,
                                             t_start_pause=T_START_PAUSE,
                                             t_stop_pause=T_STOP_PAUSE,
                                             t_stop_traffic=T_STOP_TRAFFIC,
                                             storm_detection_time=STORM_DETECTION_TIME,
                                             storm_restoration_time=STORM_RESTORATION_TIME,
                                             tolerance_percent=TOLERANCE_PERCENT)


def __create_tgen_config_two_senders_two_receivers__(api,
                                                     port_id,
                                                     prio,
                                                     duthost,
                                                     conn_graph_facts,
                                                     fanout_graph_facts,
                                                     traffic_line_rate,
                                                     start_delay,
                                                     pause_line_rate,
                                                     frame_size,
                                                     t_start_pause):

    """
    Tgen configuration 

    @param api: open tgen api fixture
    @param port_id: starting index of port_id from topo file 
    @param prio: dscp priority
    @param duthost: Sonic DUT duthost fixture
    @param conn_graph_facts: conn_graph_facts fixture to get testbed connection information
    @param fanout_graph_facts: fanout_graph_facts fixture to get testbed connection information
    @param traffic_line_rate: rate percentage of test traffic
    @param start_delay: time delay(seconds) to start traffic once start traffic is initiated globally in tgen
    @param pause_line_rate: rate percentage of Pause Storm traffic
    @param frame_size: The packet size that is sent from tgen
    @param t_start_pause: Time at which Pause Storm to be started once traffic engine starts sending traffic
    """
    vlan_subnet = get_vlan_subnet(duthost)
    if vlan_subnet is None:
        pytest_assert(False,
                      "Fail to get Vlan subnet information")

    vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, 3)

    gw_addr = vlan_subnet.split('/')[0]
    network_prefix = vlan_subnet.split('/')[1]

    device1_ip = vlan_ip_addrs[0]
    device2_ip = vlan_ip_addrs[1]
    device3_ip = vlan_ip_addrs[2]

    device1_gateway_ip = gw_addr
    device2_gateway_ip = gw_addr
    device3_gateway_ip = gw_addr

    ports_config = PortsConfig(conn_graph_facts,fanout_graph_facts)
    ports_config.verify_required_ports(no_of_ports_required=3)

    ports_list = ports_config.create_ports_list(no_of_ports=3,start_index=port_id)

    config = ports_config.l1_config(ports_list)

    line_rate = traffic_line_rate

    ######################################################################
    # Device Configuration
    ######################################################################
    port1 = config.ports[0]
    port2 = config.ports[1]
    port3 = config.ports[2]

    # Device 1 configuration
    device1 = Device('Device 1',
                     container_name=port1.name,
                     choice=Ipv4(name='Ipv4-1',
                                 address=Pattern(device1_ip),
                                 prefix=Pattern(network_prefix),
                                 gateway=Pattern(device1_gateway_ip),
                                 ethernet=Ethernet(name='Ethernet-1')))

    config.devices.append(device1)                           

    # Device 2 configuration
    device2 = Device('Device 2',
                     container_name=port2.name,
                     choice=Ipv4(name='Ipv4-2',
                                 address=Pattern(device2_ip),
                                 prefix=Pattern(network_prefix),
                                 gateway=Pattern(device2_gateway_ip),
                                 ethernet=Ethernet(name='Ethernet-2')))
                            
    config.devices.append(device2)                        

    # Device 3 configuration
    device3 = Device('Device 3',
                     container_name=port3.name,
                     choice=Ipv4(name='Ipv4-3',
                                 address=Pattern(device3_ip),
                                 prefix=Pattern(network_prefix),
                                 gateway=Pattern(device3_gateway_ip),
                                 ethernet=Ethernet(name='Ethernet-3')))

    config.devices.append(device3)                            

    ######################################################################
    # Traffic configuration Traffic 1->2
    ######################################################################

    dscp_prio = Priority(Dscp(phb=FieldPattern(choice=[str(prio)])))

    flow_1to2 = Flow(name="Traffic 1->2",
                     tx_rx=TxRx(DeviceTxRx(tx_device_names=[device1.name], rx_device_names=[device2.name])),
                     packet=[
                         Header(choice=EthernetHeader()),
                         Header(choice=Ipv4Header(priority=dscp_prio)),
                     ],
                     size=Size(frame_size),
                     rate=Rate('line', line_rate),
                     duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                     )

    config.flows.append(flow_1to2)

    ######################################################################
    # Traffic configuration Traffic 2->1
    ######################################################################

    flow_2to1 = Flow(name="Traffic 2->1",
                     tx_rx=TxRx(DeviceTxRx(tx_device_names=[device2.name], rx_device_names=[device1.name])),
                     packet=[
                         Header(choice=EthernetHeader()),
                         Header(choice=Ipv4Header(priority=dscp_prio)),
                     ],
                     size=Size(frame_size),
                     rate=Rate('line', line_rate),
                     duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                     )

    config.flows.append(flow_2to1)
    ######################################################################
    # Traffic configuration Traffic 2->3
    #######################################################################

    flow_2to3 = Flow(name="Traffic 2->3",
                     tx_rx=TxRx(DeviceTxRx(tx_device_names=[device2.name], rx_device_names=[device3.name])),
                     packet=[
                         Header(choice=EthernetHeader()),
                         Header(choice=Ipv4Header(priority=dscp_prio)),
                     ],
                     size=Size(frame_size),
                     rate=Rate('line', line_rate),
                     duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                     )

    config.flows.append(flow_2to3)

    ######################################################################
    # Traffic configuration Traffic 3->2
    #######################################################################

    flow_3to2 = Flow(name="Traffic 3->2",
                     tx_rx=TxRx(DeviceTxRx(tx_device_names=[device3.name], rx_device_names=[device2.name])),
                     packet=[
                         Header(choice=EthernetHeader()),
                         Header(choice=Ipv4Header(priority=dscp_prio)),
                     ],
                     size=Size(frame_size),
                     rate=Rate('line', line_rate),
                     duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                     )

    config.flows.append(flow_3to2)

    #######################################################################
    # Traffic configuration Pause
    #######################################################################
    
    if type(prio) is not list:
        prio = map(int,str(prio))
    pause = create_pause_packet(prio)
    
    pause_flow = Flow(name='Pause Storm',
                      tx_rx=TxRx(PortTxRx(tx_port_name=port3.name, rx_port_names=[port3.name])),
                      packet=[pause],
                      size=Size(64),
                      rate=Rate('line', value=pause_line_rate),
                      duration=Duration(Continuous(delay=t_start_pause * (10 ** 9), delay_unit='nanoseconds'))
                      )

    config.flows.append(pause_flow)
    api.set_state(State(ConfigState(config=config, state='set')))


def __pfcwd_two_senders_two_receivers_test__(api,
                                             duthost,
                                             start_delay,
                                             t_start_pause,
                                             t_stop_pause,
                                             t_stop_traffic,
                                             storm_detection_time,
                                             storm_restoration_time,
                                             tolerance_percent):
    """
    @param api: open tgen api fixture
    @param duthost: Sonic DUT duthost fixture
    @param start_delay: time delay(seconds) to start traffic once start traffic is initiated globally in tgen
    @param t_start_pause: Time at which Pause Storm to be started once traffic engine starts sending traffic
    @param stop_pause: Time at which Pause Storm to be stopped
    @param stop_traffic: Time at all traffic to be stopped
    @param storm_detection_time: Pause Storm detection time 
    @param storm_restoration_time: Pause Storm Restoration time
    @param tolerance_percent: Tolerance Percent
    """

    #######################################################################
    # DUT Configuration
    #######################################################################
    duthost.shell('sudo pfcwd stop')

    cmd = 'sudo pfcwd start --action drop ports all detection-time {} \
           --restoration-time {}'.format(storm_detection_time,storm_restoration_time)
    duthost.shell(cmd)

    duthost.shell('pfcwd show config')

    t_btwn_start_pause_and_stop_pause = t_stop_pause - t_start_pause
    t_btwn_stop_pause_and_stop_traffic = t_stop_traffic - t_stop_pause

    ##############################################################################################
    # Start all flows 
    # 1. check for no loss in the flows Traffic 1->2,Traffic 2->1
    # 2. check for loss in 'Traffic 2->3','Traffic 3->2' during pause storm
    ##############################################################################################
    api.set_state(State(FlowTransmitState(state='start')))

    # Sleeping till t_start_pause as t_start_pause is added as delay for the flow
    time.sleep(start_delay+t_start_pause)

    t_to_stop_pause = datetime.datetime.now() + datetime.timedelta(seconds=t_btwn_start_pause_and_stop_pause)

    #Check for traffic observations for two timestamps in t_btwn_start_pause_and_stop_pause
    while True:
        if datetime.datetime.now() >= t_to_stop_pause:
            break
        else:
            time.sleep(t_btwn_start_pause_and_stop_pause/2)   
            # Get statistics
            test_stat = api.get_flow_results(FlowRequest())
            for flow in test_stat :
                if flow['name'] in ['Traffic 1->2','Traffic 2->1'] :
                    tx_frame_rate = int(flow['frames_tx_rate'])
                    rx_frame_rate = int(flow['frames_rx_rate'])
                    tolerance = (tx_frame_rate * tolerance_percent)/100
                    logger.info("\n{} during Pause Storm Tx Frame Rate: {} Rx Frame Rate: {} \
                                    \n{} during Pause Storm Tx Frames: {} Rx Frames: {} Loss%: {}"
                                .format(flow['name'],tx_frame_rate,rx_frame_rate,flow['name'],
                                        flow['frames_tx'],flow['frames_rx'],flow['loss']))
                    if tx_frame_rate > (rx_frame_rate + tolerance):
                        pytest_assert(False,
                                      "Observing loss for %s during pause storm which is not expected" %(flow['name']))
                elif flow['name'] in ['Traffic 2->3','Traffic 3->2']:
                    tx_frame_rate = int(flow['frames_tx_rate'])
                    rx_frame_rate = int(flow['frames_rx_rate'])
                    logger.info("\n{} during Pause Storm Tx Frame Rate: {} Rx Frame Rate: {} \
                                    \n{} during Pause Storm Tx Frames: {} Rx Frames: {} Loss%: {}"
                                .format(flow['name'],tx_frame_rate,rx_frame_rate,flow['name'],
                                        flow['frames_tx'],flow['frames_rx'],flow['loss']))
                    if (tx_frame_rate == 0) or (rx_frame_rate != 0):
                        pytest_assert(False,
                                      "Expecting loss for %s during pause storm, which didn't occur" %(flow['name']))
                
    ###############################################################################################
    # Stop Pause Storm
    # 1. check for no loss in the flows Traffic 1->2,Traffic 2->1
    # 2. check for no loss in 'Traffic 2->3','Traffic 3->2' after stopping Pause Storm
    ###############################################################################################
    # pause storm will stop once loop completes, once the current time reaches t_stop_pause
    api.set_state(State(FlowTransmitState(state='stop',flow_names=['Pause Storm'])))
    logger.info("PFC Pause Storm stopped")
    
    # Verification after pause storm is stopped
    t_to_stop_traffic = datetime.datetime.now() + datetime.timedelta(seconds=t_btwn_stop_pause_and_stop_traffic)
    
    # Check for traffic observations for two timestamps in t_btwn_stop_pause_and_stop_traffic
    while True:
        if datetime.datetime.now() >= t_to_stop_traffic:
            break
        else:
            time.sleep(t_btwn_stop_pause_and_stop_traffic/2)
            # Get statistics
            test_stat = api.get_flow_results(FlowRequest())
            
            for flow in test_stat:
                if flow['name'] in ['Traffic 1->2','Traffic 2->1','Traffic 2->3','Traffic 3->2']:
                    tx_frame_rate = int(flow['frames_tx_rate'])
                    rx_frame_rate = int(flow['frames_rx_rate'])
                    tolerance = (tx_frame_rate * tolerance_percent)/100
                    logger.info("\n{} after stopping Pause Storm Tx Frame Rate: {} Rx Frame Rate: {} \
                                    \n{} after stopping Pause Storm Tx Frames: {} Rx Frames: {} Loss%: {}"
                                .format(flow['name'],tx_frame_rate,rx_frame_rate,flow['name'],
                                        flow['frames_tx'],flow['frames_rx'],flow['loss']))
                    if tx_frame_rate > (rx_frame_rate + tolerance):
                        pytest_assert(False,
                                      "Observing loss for %s after pause storm stopped which is not expected" %(flow['name']))
    
    # stop all flows
    api.set_state(State(FlowTransmitState(state='stop')))


# pfcwd all to all
def run_basic_pfcwd_all_to_all_test(api,
                                    port_id,
                                    prio,
                                    duthost,
                                    conn_graph_facts,
                                    fanout_graph_facts):

    """
    PFCWD all senders all receivers test

    @param api: open tgen api fixture
    @param port_id: starting index of port_id from topo file 
    @param prio: dscp priority
    @param duthost: Sonic DUT duthost fixture
    @param conn_graph_facts: conn_graph_facts fixture to get testbed connection information
    @param fanout_graph_facts: fanout_graph_facts fixture to get testbed connection information
    """

    __create_tgen_config_all_to_all__(api=api,
                                      port_id=port_id,
                                      prio=prio,
                                      duthost=duthost,
                                      conn_graph_facts=conn_graph_facts,
                                      fanout_graph_facts=fanout_graph_facts,
                                      traffic_line_rate=TRAFFIC_LINE_RATE,
                                      start_delay=START_DELAY,
                                      pause_line_rate=PAUSE_LINE_RATE,
                                      frame_size=FRAME_SIZE,
                                      t_start_pause=T_START_PAUSE)

    __pfcwd_all_to_all_test__(api=api,
                              duthost=duthost,
                              start_delay=START_DELAY,
                              t_start_pause=T_START_PAUSE,
                              t_stop_pause=T_STOP_PAUSE,
                              t_stop_traffic=T_STOP_TRAFFIC,
                              storm_detection_time=STORM_DETECTION_TIME,
                              storm_restoration_time=STORM_RESTORATION_TIME,
                              tolerance_percent=TOLERANCE_PERCENT)


def __create_tgen_config_all_to_all__(api,
                                      port_id,
                                      prio,
                                      duthost,
                                      conn_graph_facts,
                                      fanout_graph_facts,
                                      traffic_line_rate,
                                      start_delay,
                                      pause_line_rate,
                                      frame_size,
                                      t_start_pause):
    """                                  

    Tgen configuration 

    @param api: open tgen api fixture
    @param port_id: starting index of port_id from topo file 
    @param prio: dscp priority
    @param duthost: Sonic DUT duthost fixture
    @param conn_graph_facts: conn_graph_facts fixture to get testbed connection information
    @param fanout_graph_facts: fanout_graph_facts fixture to get testbed connection information
    @param traffic_line_rate: rate percentage of test traffic
    @param start_delay: time delay(seconds) to start traffic once start traffic is initiated globally in tgen
    @param pause_line_rate: rate percentage of Pause Storm traffic
    @param frame_size: The packet size that is sent from tgen
    @param t_start_pause: Time at which Pause Storm to be started once traffic engine starts sending traffic
    """

    vlan_subnet = get_vlan_subnet(duthost)
    if vlan_subnet is None:
        pytest_assert(False,
                      "Fail to get Vlan subnet information")

    vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, 3)

    gw_addr = vlan_subnet.split('/')[0]
    network_prefix = vlan_subnet.split('/')[1]

    device1_ip = vlan_ip_addrs[0]
    device2_ip = vlan_ip_addrs[1]
    device3_ip = vlan_ip_addrs[2]

    device1_gateway_ip = gw_addr
    device2_gateway_ip = gw_addr
    device3_gateway_ip = gw_addr

    ports_config = PortsConfig(conn_graph_facts,fanout_graph_facts)
    ports_config.verify_required_ports(no_of_ports_required=3)

    ports_list = ports_config.create_ports_list(no_of_ports=3,start_index=port_id)

    config = ports_config.l1_config(ports_list)

    line_rate = traffic_line_rate

    ######################################################################
    # Device Configuration
    ######################################################################
    port1 = config.ports[0]
    port2 = config.ports[1]
    port3 = config.ports[2]

    # Device 1 configuration
    device1 = Device('Device 1',
                     container_name=port1.name,
                     choice=Ipv4(name='Ipv4-1',
                                 address=Pattern(device1_ip),
                                 prefix=Pattern(network_prefix),
                                 gateway=Pattern(device1_gateway_ip),
                                 ethernet=Ethernet(name='Ethernet-1')))

    config.devices.append(device1)                           

    # Device 2 configuration
    device2 = Device('Device 2',
                     container_name=port2.name,
                     choice=Ipv4(name='Ipv4-2',
                                 address=Pattern(device2_ip),
                                 prefix=Pattern(network_prefix),
                                 gateway=Pattern(device2_gateway_ip),
                                 ethernet=Ethernet(name='Ethernet-2')))
                            
    config.devices.append(device2)                        

    # Device 3 configuration
    device3 = Device('Device 3',
                     container_name=port3.name,
                     choice=Ipv4(name='Ipv4-3',
                                 address=Pattern(device3_ip),
                                 prefix=Pattern(network_prefix),
                                 gateway=Pattern(device3_gateway_ip),
                                 ethernet=Ethernet(name='Ethernet-3')))

    config.devices.append(device3)                            

    ######################################################################
    # Traffic configuration Traffic 1->2
    ######################################################################

    dscp_prio = Priority(Dscp(phb=FieldPattern(choice=[str(prio)])))

    flow_1to2 = Flow(name="Traffic 1->2",
                     tx_rx=TxRx(DeviceTxRx(tx_device_names=[device1.name], rx_device_names=[device2.name])),
                     packet=[
                         Header(choice=EthernetHeader()),
                         Header(choice=Ipv4Header(priority=dscp_prio)),
                     ],
                     size=Size(frame_size),
                     rate=Rate('line', line_rate),
                     duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                     )

    config.flows.append(flow_1to2)

    ######################################################################
    # Traffic configuration Traffic 2->1
    ######################################################################

    flow_2to1 = Flow(name="Traffic 2->1",
                     tx_rx=TxRx(DeviceTxRx(tx_device_names=[device2.name], rx_device_names=[device1.name])),
                     packet=[
                         Header(choice=EthernetHeader()),
                         Header(choice=Ipv4Header(priority=dscp_prio)),
                     ],
                     size=Size(frame_size),
                     rate=Rate('line', line_rate),
                     duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                     )

    config.flows.append(flow_2to1)
    ######################################################################
    # Traffic configuration Traffic 2->3
    #######################################################################

    flow_2to3 = Flow(name="Traffic 2->3",
                     tx_rx=TxRx(DeviceTxRx(tx_device_names=[device2.name], rx_device_names=[device3.name])),
                     packet=[
                         Header(choice=EthernetHeader()),
                         Header(choice=Ipv4Header(priority=dscp_prio)),
                     ],
                     size=Size(frame_size),
                     rate=Rate('line', line_rate),
                     duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                     )

    config.flows.append(flow_2to3)

    ######################################################################
    # Traffic configuration Traffic 3->2
    #######################################################################

    flow_3to2 = Flow(name="Traffic 3->2",
                     tx_rx=TxRx(DeviceTxRx(tx_device_names=[device3.name], rx_device_names=[device2.name])),
                     packet=[
                         Header(choice=EthernetHeader()),
                         Header(choice=Ipv4Header(priority=dscp_prio)),
                     ],
                     size=Size(frame_size),
                     rate=Rate('line', line_rate),
                     duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                     )

    config.flows.append(flow_3to2)

    ######################################################################
    # Traffic configuration Traffic 1->3
    #######################################################################

    flow_1to3 = Flow(name="Traffic 1->3",
                     tx_rx=TxRx(DeviceTxRx(tx_device_names=[device1.name], rx_device_names=[device3.name])),
                     packet=[
                         Header(choice=EthernetHeader()),
                         Header(choice=Ipv4Header(priority=dscp_prio)),
                     ],
                     size=Size(frame_size),
                     rate=Rate('line', line_rate),
                     duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                     )

    config.flows.append(flow_1to3)

    ######################################################################
    # Traffic configuration Traffic 3->1
    #######################################################################

    flow_3to1 = Flow(name="Traffic 3->1",
                     tx_rx=TxRx(DeviceTxRx(tx_device_names=[device3.name], rx_device_names=[device1.name])),
                     packet=[
                         Header(choice=EthernetHeader()),
                         Header(choice=Ipv4Header(priority=dscp_prio)),
                     ],
                     size=Size(frame_size),
                     rate=Rate('line', line_rate),
                     duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                     )

    config.flows.append(flow_3to1)

    #######################################################################
    # Traffic configuration Pause
    #######################################################################
    
    if type(prio) is not list:
        prio = map(int,str(prio))
    pause = create_pause_packet(prio)
    
    pause_flow = Flow(name='Pause Storm',
                      tx_rx=TxRx(PortTxRx(tx_port_name=port3.name, rx_port_names=[port3.name])),
                      packet=[pause],
                      size=Size(64),
                      rate=Rate('line', value=pause_line_rate),
                      duration=Duration(Continuous(delay=t_start_pause * (10 ** 9), delay_unit='nanoseconds'))
                      )

    config.flows.append(pause_flow)

    api.set_state(State(ConfigState(config=config, state='set')))


def __pfcwd_all_to_all_test__(api,
                              duthost,
                              start_delay,
                              t_start_pause,
                              t_stop_pause,
                              t_stop_traffic,
                              storm_detection_time,
                              storm_restoration_time,
                              tolerance_percent):

    """
    @param api: open tgen api fixture
    @param duthost: Sonic DUT duthost fixture
    @param start_delay: time delay(seconds) to start traffic once start traffic is initiated globally in tgen
    @param t_start_pause: Time at which Pause Storm to be started once traffic engine starts sending traffic
    @param stop_pause: Time at which Pause Storm to be stopped
    @param stop_traffic: Time at all traffic to be stopped
    @param storm_detection_time: Pause Storm detection time 
    @param storm_restoration_time: Pause Storm Restoration time
    @param tolerance_percent: Tolerance Percent
    """

    #######################################################################
    # DUT Configuration
    #######################################################################
    duthost.shell('sudo pfcwd stop')

    cmd = 'sudo pfcwd start --action drop ports all detection-time {} \
           --restoration-time {}'.format(storm_detection_time,storm_restoration_time)
    duthost.shell(cmd)

    duthost.shell('pfcwd show config')
    
    t_btwn_start_pause_and_stop_pause = t_stop_pause - t_start_pause
    t_btwn_stop_pause_and_stop_traffic = t_stop_traffic - t_stop_pause

    ###############################################################################################
    # Start all flows 
    # 1. check for no loss in the flows Traffic 1->2,Traffic 2->1
    # 2. check for loss in 'Traffic 2->3','Traffic 3->2','Traffic 1->3','Traffic 3->1' 
    #    during pause storm
    ###############################################################################################
    
    api.set_state(State(FlowTransmitState(state='start')))
    
    # Sleeping till t_start_pause as t_start_pause is added as start_delay to the flow 
    time.sleep(start_delay + t_start_pause)
    
    t_to_stop_pause  = datetime.datetime.now() + datetime.timedelta(seconds=t_btwn_start_pause_and_stop_pause)

    #Check for traffic observations for two timestamps in t_btwn_start_pause_and_stop_pause
    while True:
        if datetime.datetime.now() >= t_to_stop_pause:
            break
        else:
            time.sleep(t_btwn_start_pause_and_stop_pause/2)   
            # Get statistics
            test_stat = api.get_flow_results(FlowRequest())
            
            for flow in test_stat :
                if flow['name'] in ['Traffic 1->2','Traffic 2->1'] :
                    tx_frame_rate = int(flow['frames_tx_rate'])
                    rx_frame_rate = int(flow['frames_rx_rate'])
                    tolerance = (tx_frame_rate * tolerance_percent)/100
                    logger.info("\n{} during Pause Storm Tx Frame Rate: {} Rx Frame Rate: {} \
                                    \n{} during Pause Storm Tx Frames: {} Rx Frames: {} Loss%: {}"
                                .format(flow['name'],tx_frame_rate,rx_frame_rate,flow['name'],
                                        flow['frames_tx'],flow['frames_rx'],flow['loss']))
                    if tx_frame_rate > (rx_frame_rate + tolerance):
                        pytest_assert(False,
                                        "Observing loss for %s during pause storm which is not expected" %(flow['name']))
                elif flow['name'] in ['Traffic 2->3','Traffic 3->2','Traffic 1->3','Traffic 3->1']:
                    tx_frame_rate = int(flow['frames_tx_rate'])
                    rx_frame_rate = int(flow['frames_rx_rate'])
                    logger.info("\n{} during Pause Storm Tx Frame Rate: {} Rx Frame Rate: {} \
                                    \n{} during Pause Storm Tx Frames: {} Rx Frames: {} Loss%: {}"
                                .format(flow['name'],tx_frame_rate,rx_frame_rate,flow['name'],
                                        flow['frames_tx'],flow['frames_rx'],flow['loss']))
                    if (tx_frame_rate == 0 ) or (rx_frame_rate != 0):
                        pytest_assert(False,
                                        "Expecting loss for %s during pause storm, which didn't occur" %(flow['name']))
                
    ###############################################################################################
    # Stop Pause Storm
    # 1. check for no loss in the flows Traffic 1->2,Traffic 2->1
    # 2. check for no loss in 'Traffic 2->3','Traffic 3->2','Traffic 1->3','Traffic 3->1'
    #    after stopping Pause Storm
    ###############################################################################################
    # pause storm will stop once loop completes,the current time reaches t_stop_pause
    api.set_state(State(FlowTransmitState(state='stop',flow_names=['Pause Storm'])))
    logger.info("PFC Pause Storm stopped")
    # Verification after pause storm is stopped
    t_to_stop_traffic = datetime.datetime.now() + datetime.timedelta(seconds=t_btwn_stop_pause_and_stop_traffic)
    
    #Check for traffic observations for two timestamps in t_btwn_stop_pause_and_stop_traffic
    while True:
        if datetime.datetime.now() >= t_to_stop_traffic:
            break
        else:
            time.sleep(t_btwn_stop_pause_and_stop_traffic/2)
            # Get statistics
            test_stat = api.get_flow_results(FlowRequest())
            
            for flow in test_stat:
                if flow['name'] in ['Traffic 1->2','Traffic 2->1','Traffic 2->3',
                                    'Traffic 3->2','Traffic 1->3','Traffic 3->1']:
                    tx_frame_rate = int(flow['frames_tx_rate'])
                    rx_frame_rate = int(flow['frames_rx_rate'])
                    tolerance = (tx_frame_rate * tolerance_percent)/100
                    logger.info("\n{} after stopping Pause Storm Tx Frame Rate: {} Rx Frame Rate: {} \
                                    \n{} after stopping Pause Storm Tx Frames: {} Rx Frames: {} Loss%: {}"
                                .format(flow['name'],tx_frame_rate,rx_frame_rate,flow['name'],
                                        flow['frames_tx'],flow['frames_rx'],flow['loss']))
                    if tx_frame_rate > (rx_frame_rate + tolerance):
                        pytest_assert(False,
                                        "Observing loss for %s after pause storm stopped which is not expected" %(flow['name']))
    
    # stop all flows
    api.set_state(State(FlowTransmitState(state='stop')))


# pfc disabled pfcwd enabled
def run_pfc_disabled_pfcwd_enabled(api,
                                   port_id,
                                   prio,
                                   duthost,
                                   conn_graph_facts,
                                   fanout_graph_facts):

    """
    PFC disabled pfcwd enabled test

    @param api: open tgen api fixture
    @param port_id: starting index of port_id from topo file 
    @param prio: dscp priority
    @param duthost: Sonic DUT duthost fixture
    @param conn_graph_facts: conn_graph_facts fixture to get testbed connection information
    @param fanout_graph_facts: fanout_graph_facts fixture to get testbed connection information
    """

    __create_tgen_config_pfc_disabled_pfcwd_enabled__(api=api,
                                                      port_id=port_id,
                                                      prio=prio,
                                                      duthost=duthost,
                                                      conn_graph_facts=conn_graph_facts,
                                                      fanout_graph_facts=fanout_graph_facts,
                                                      traffic_line_rate=TRAFFIC_LINE_RATE,
                                                      start_delay=START_DELAY,
                                                      pause_line_rate=PAUSE_LINE_RATE,
                                                      frame_size=FRAME_SIZE,
                                                      t_start_pause=T_START_PAUSE)

    __pfc_disabled_pfcwd_enabled_test__(api=api,
                                        duthost=duthost,
                                        prio=prio,
                                        start_delay=START_DELAY,
                                        t_start_pause=T_START_PAUSE,
                                        storm_detection_time=STORM_DETECTION_TIME,
                                        storm_restoration_time=STORM_RESTORATION_TIME,
                                        tolerance_percent=TOLERANCE_PERCENT)


def __create_tgen_config_pfc_disabled_pfcwd_enabled__(api,
                                                      port_id,
                                                      prio,
                                                      duthost,
                                                      conn_graph_facts,
                                                      fanout_graph_facts,
                                                      traffic_line_rate,
                                                      start_delay,
                                                      pause_line_rate,
                                                      frame_size,
                                                      t_start_pause):

    """
    Tgen configuration 

    @param api: open tgen api fixture
    @param port_id: starting index of port_id from topo file 
    @param prio: dscp priority
    @param duthost: Sonic DUT duthost fixture
    @param conn_graph_facts: conn_graph_facts fixture to get testbed connection information
    @param fanout_graph_facts: fanout_graph_facts fixture to get testbed connection information
    @param traffic_line_rate: rate percentage of test traffic
    @param start_delay: time delay(seconds) to start traffic once start traffic is initiated globally in tgen
    @param pause_line_rate: rate percentage of Pause Storm traffic
    @param frame_size: The packet size that is sent from tgen
    @param t_start_pause: Time at which Pause Storm to be started once traffic engine starts sending traffic
    """

    vlan_subnet = get_vlan_subnet(duthost)
    if vlan_subnet is None:
        pytest_assert(False,
                      "Fail to get Vlan subnet information")

    vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, 3)

    gw_addr = vlan_subnet.split('/')[0]
    network_prefix = vlan_subnet.split('/')[1]

    device1_ip = vlan_ip_addrs[0]
    device2_ip = vlan_ip_addrs[1]

    device1_gateway_ip = gw_addr
    device2_gateway_ip = gw_addr

    ports_config = PortsConfig(conn_graph_facts,fanout_graph_facts)
    ports_config.verify_required_ports(no_of_ports_required=2)

    ports_list = ports_config.create_ports_list(no_of_ports=2,start_index=port_id)

    config = ports_config.l1_config(ports_list)

    line_rate = traffic_line_rate

    ######################################################################
    # Device Configuration
    ######################################################################
    port1 = config.ports[0]
    port2 = config.ports[1]

    # Device 1 configuration
    device1 = Device('Device 1',
                     container_name=port1.name,
                     choice=Ipv4(name='Ipv4-1',
                                 address=Pattern(device1_ip),
                                 prefix=Pattern(network_prefix),
                                 gateway=Pattern(device1_gateway_ip),
                                 ethernet=Ethernet(name='Ethernet-1')))

    config.devices.append(device1)                           

    # Device 2 configuration
    device2 = Device('Device 2',
                     container_name=port2.name,
                     choice=Ipv4(name='Ipv4-2',
                                 address=Pattern(device2_ip),
                                 prefix=Pattern(network_prefix),
                                 gateway=Pattern(device2_gateway_ip),
                                 ethernet=Ethernet(name='Ethernet-2')))
                            
    config.devices.append(device2)                                                    

    ######################################################################
    # Traffic configuration Traffic 1->2
    ######################################################################

    dscp_prio = Priority(Dscp(phb=FieldPattern(choice=[str(prio)])))

    flow_1to2 = Flow(name="Traffic 1->2",
                     tx_rx=TxRx(DeviceTxRx(tx_device_names=[device1.name], rx_device_names=[device2.name])),
                     packet=[
                         Header(choice=EthernetHeader()),
                         Header(choice=Ipv4Header(priority=dscp_prio)),
                     ],
                     size=Size(frame_size),
                     rate=Rate('line', line_rate),
                     duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                     )

    config.flows.append(flow_1to2)

    ######################################################################
    # Traffic configuration Traffic 2->1
    ######################################################################

    flow_2to1 = Flow(name="Traffic 2->1",
                     tx_rx=TxRx(DeviceTxRx(tx_device_names=[device2.name], rx_device_names=[device1.name])),
                     packet=[
                         Header(choice=EthernetHeader()),
                         Header(choice=Ipv4Header(priority=dscp_prio)),
                     ],
                     size=Size(frame_size),
                     rate=Rate('line', line_rate),
                     duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                     )

    config.flows.append(flow_2to1)

    #######################################################################
    # Traffic configuration Pause
    #######################################################################
    
    if type(prio) is not list:
        prio = map(int,str(prio))
    pause = create_pause_packet(prio)
    
    pause_flow = Flow(name='Pause Storm',
                      tx_rx=TxRx(PortTxRx(tx_port_name=port2.name, rx_port_names=[port2.name])),
                      packet=[pause],
                      size=Size(64),
                      rate=Rate('line', value=pause_line_rate),
                      duration=Duration(Continuous(delay=t_start_pause * (10 ** 9), delay_unit='nanoseconds'))
                      )

    config.flows.append(pause_flow)

    api.set_state(State(ConfigState(config=config, state='set')))


def __pfc_disabled_pfcwd_enabled_test__(api,
                                        duthost,
                                        prio,
                                        start_delay,
                                        t_start_pause,
                                        storm_detection_time,
                                        storm_restoration_time,
                                        tolerance_percent):

    """
    @param api: open tgen api fixture
    @param duthost: Sonic DUT duthost fixture
    @param start_delay: time delay(seconds) to start traffic once start traffic is initiated globally in tgen
    @param t_start_pause: Time at which Pause Storm to be started once traffic engine starts sending traffic
    @param storm_detection_time: Pause Storm detection time 
    @param storm_restoration_time: Pause Storm Restoration time
    @param tolerance_percent: Tolerance Percent
    """

    ########################################################################################
    # DUT Configuration
    # Note : The test is done considering the DUT has lossless priorities configured as 3,4
    ########################################################################################
    #take config backup
    duthost.shell("sudo cp /etc/sonic/config_db.json /tmp/config_db_pfc.json")

    logger.info("Test for priority {}".format(prio))
    if prio == 3:
        duthost.replace(path="/etc/sonic/config_db.json", 
                        regexp='"pfc_enable": ".*"', 
                        replace='"pfc_enable": "{0}"'.format(4))
    elif prio == 4:
        duthost.replace(path="/etc/sonic/config_db.json", 
                        regexp='"pfc_enable": ".*"',
                        replace='"pfc_enable": "{0}"'.format(3))

    duthost.shell("sudo config reload -y")
    time.sleep(90)

    duthost.shell('sudo pfcwd stop')

    cmd = 'sudo pfcwd start --action drop ports all detection-time {} \
        --restoration-time {}'.format(storm_detection_time,storm_restoration_time)
    duthost.shell(cmd)

    duthost.shell('pfcwd show config')
    
    ###############################################################################################
    # Start all flows 
    # 1. check for no loss in the flows Traffic 1->2,Traffic 2->1
    ###############################################################################################
    
    api.set_state(State(FlowTransmitState(state='start')))

    # Sleeping till t_start_pause as t_start_pause is added as delay for the flow
    time.sleep(start_delay+t_start_pause)

    # Keep checking traffic for 10 seconds
    from pandas import DataFrame
    retry = 0
    while True:
        time.sleep(2)
        retry = retry + 1
        for flow in ['Traffic 1->2','Traffic 2->1']:
            request = FlowRequest(flow_names=[flow])
            results = api.get_flow_results(request)
            df = DataFrame.from_dict(results)
            tolerance = (df.frames_tx * tolerance_percent) / 100
            logger.info("\n{} during Pause Storm Tx Frames: {} Rx Frames: {} Loss%: {}"
                        .format(df.name[0],df.frames_tx[0],df.frames_rx[0],df.loss[0]))
            if df.frames_tx.sum() > df.frames_rx.sum() + int(tolerance):
                pytest_assert(False,
                              "Observing loss for %s during pause storm which is not expected" % (df.name))
        if retry == 5:
            break
    
    # stop all flows
    api.set_state(State(FlowTransmitState(state='stop')))

    output = duthost.command("pfcwd show stats")["stdout_lines"]
    for each_line in output:
        if 'Ethernet' in each_line:
            pytest_assert(False,
                          "PFCWD triggered on ports which is not expected")

    # Revert the config to original
    duthost.shell("sudo rm -rf /etc/sonic/config_db.json")
    duthost.shell("sudo cp /tmp/config_db_pfc.json /etc/sonic/config_db.json")
    duthost.shell("sudo config reload -y")
