import time
import pytest
import sys

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
from abstract_open_traffic_generator.result import PortRequest
from abstract_open_traffic_generator.config import Options
from abstract_open_traffic_generator.config import Config
from abstract_open_traffic_generator.capture import *

from abstract_open_traffic_generator.control import *
from abstract_open_traffic_generator.port import *
from abstract_open_traffic_generator.result import FlowRequest, CaptureRequest


from abstract_open_traffic_generator.layer1 import\
    Layer1, OneHundredGbe, FlowControl, Ieee8021qbb

from abstract_open_traffic_generator.device import\
     Device, Ethernet, Vlan, Ipv4, Pattern

from abstract_open_traffic_generator.flow import\
    DeviceTxRx, TxRx, Flow, Header, Size, Rate,\
    Duration, FixedPackets, PortTxRx, PfcPause, Counter, Random,\
    EthernetPause, FixedSeconds, Continuous

from abstract_open_traffic_generator.flow_ipv4 import\
    Priority, Dscp

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
           s += 2**7
    return "%x"%(s)


sec_to_nano_sec = lambda x : x * 1000000000.0
def __base_configs__(conn_graph_facts,
                     duthost,
                     lossless_prio_dscp_map,
                     l1_config,
                     start_delay_secs,
                     traffic_duration,
                     pause_line_rate,
                     traffic_line_rate,
                     frame_size,
                     ecn_thresholds,
                     number_of_packets,
                     test_flow_name) :

    test_dscp_list = [str(prio) for prio in lossless_prio_dscp_map]

    tx = l1_config.ports[0]
    rx = l1_config.ports[1]

    vlan_subnet = get_vlan_subnet(duthost)
    pytest_assert(vlan_subnet is not None,
                  "Fail to get Vlan subnet information")

    vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, 2)

    gw_addr = vlan_subnet.split('/')[0]
    interface_ip_addr = vlan_ip_addrs[0]

    tx_port_ip = vlan_ip_addrs[1]
    rx_port_ip = vlan_ip_addrs[0]

    tx_gateway_ip = gw_addr
    rx_gateway_ip = gw_addr

    test_line_rate = traffic_line_rate
    pause_line_rate = pause_line_rate

    pytest_assert(test_line_rate <= pause_line_rate,
        "test_line_rate + should be less than pause_line_rate")

    ######################################################################
    # Create TX stack configuration
    ######################################################################
    tx_ipv4 = Ipv4(name='Tx Ipv4',
                   address=Pattern(tx_port_ip),
                   prefix=Pattern('24'),
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
                   prefix=Pattern('24'),
                   gateway=Pattern(rx_gateway_ip),
                   ethernet=Ethernet(name='Rx Ethernet'))

    rx_device = Device(container_name=rx.name,
                       name='Rx Device',
                       device_count=1,
                       choice=rx_ipv4)

    l1_config.devices.append(rx_device)
    ######################################################################
    # Traffic configuration Test data
    ######################################################################
    data_endpoint = DeviceTxRx(
        tx_device_names=[tx_device.name],
        rx_device_names=[rx_device.name],
    )

    test_dscp = Priority(Dscp(phb=FieldPattern(choice=test_dscp_list),
                              ecn=FieldPattern(Dscp.ECN_CAPABLE_TRANSPORT_1)))

    # ecn_thresholds in bytes 
    #number_of_packets = int(2 * (ecn_thresholds / frame_size))
    delay_nano_sec = sec_to_nano_sec(start_delay_secs)
    test_flow = Flow(
        name=test_flow_name,
        tx_rx=TxRx(data_endpoint),
        packet=[
            Header(choice=EthernetHeader()),
            Header(choice=Ipv4Header(priority=test_dscp))
        ],
        size=Size(frame_size),
        rate=Rate('line', test_line_rate),
        duration=Duration(FixedPackets(packets=number_of_packets, delay=delay_nano_sec, delay_unit='nanoseconds'))
    )

    l1_config.flows.append(test_flow)

    #######################################################################
    # Traffic configuration Pause
    #######################################################################
    pause_endpoint = PortTxRx(tx_port_name='Rx', rx_port_names=['Rx'])
    # test_dscp_list = lossless priority
    p = ['0' if str(x) not in test_dscp_list else 'ffff' for x in range(8)]
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

    pause_duration = start_delay_secs + traffic_duration
    pause_flow = Flow(
        name='Pause Storm',
        tx_rx=TxRx(pause_endpoint),
        packet=[pause],
        size=Size(64),
        rate=Rate('line', value=100),
        duration=Duration(Continuous(delay=0, delay_unit='nanoseconds'))
    )

    l1_config.flows.append(pause_flow)

    return l1_config


def run_ecn_marking_at_egress(api,
                              duthost,
                              conn_graph_facts,
                              fanout_graph_facts,
                              port_id,
                              lossless_prio,
                              start_delay_secs,
                              pause_line_rate,
                              traffic_line_rate,
                              traffic_duration,
                              frame_size,
                              test_flow_name,
                              ecn_thresholds):

    number_of_packets = int(2 * (ecn_thresholds / frame_size))

    tgen_ports = TgenPorts(conn_graph_facts, fanout_graph_facts) 
    port_list = tgen_ports.create_ports_list(2, port_id)
    l1_config = tgen_ports.l1_config(port_list)

    l1_config.layer1[0].port_names = ['Tx', 'Rx']
    l1_config.ports[0].name = 'Tx'
    l1_config.ports[1].name = 'Rx'

    base_config = __base_configs__(conn_graph_facts=conn_graph_facts,
                                   duthost=duthost,
                                   lossless_prio_dscp_map=lossless_prio,
                                   l1_config=l1_config,
                                   start_delay_secs=start_delay_secs,
                                   traffic_duration=traffic_duration,
                                   pause_line_rate=pause_line_rate,
                                   traffic_line_rate=traffic_line_rate,
                                   frame_size=frame_size,
                                   ecn_thresholds=ecn_thresholds,
                                   number_of_packets=number_of_packets,
                                   test_flow_name=test_flow_name)

    rx_port=base_config.ports[1]
    # rx_port.capture = Capture(choice=[], enable=True)
    base_config.captures.append(Capture(choice=[],
                                name='Rx Capture', 
                                enable=True, 
                                port_names=[rx_port.name]))

    # create the configuration
    api.set_state(State(ConfigState(config=base_config, state='set')))

    # start capture
    api.set_state(State(PortCaptureState(port_names=[rx_port.name], state='start')))

    # start all flows
    api.set_state(State(FlowTransmitState(state='start')))

    exp_dur = start_delay_secs + traffic_duration
    logger.info("Traffic is running for %s seconds" %(traffic_duration))
    time.sleep(exp_dur)

    # stop all flows
    api.set_state(State(FlowTransmitState(state='stop')))

    pcap_bytes = api.get_capture_results(CaptureRequest(port_name=rx_port.name))

    # Get statistics
    for row in api.get_flow_results(FlowRequest(flow_names=[test_flow_name])):
        if (row['name'] == test_flow_name) :
            if ((row['frames_rx'] == 0) or (row['frames_tx'] != row['frames_rx'])):
                logger.error("Tx = %s Rx = %s" % (row['frames_tx'], row['frames_rx']))
                pytest.fail("Not all %s reached Rx End")

    # write the pcap bytes to a local file
    with open('%s.pcap' % rx_port.name, 'wb') as fid:
        fid.write(b'%s'%(pcap_bytes))

    from scapy.all import rdpcap
    reader = rdpcap('%s.pcap' % rx_port.name)

    ip_packet = filter(lambda x : x.haslayer('IP'), reader)

    if ((ip_packet[0]['IP'].getfieldval('tos') & 3 != 3) or
        (ip_packet[-1]['IP'].getfieldval('tos') & 3 != 2)) :
        p = [x['IP'].getfieldval('tos') for x in ip_packet]
        logger.error("dumping dscp-ECN field %s" %(p))
        pytest.fail("1st should be ECN marked & last packet should be ECN marked")



def run_marking_accuracy(api,
                         duthost,
                         conn_graph_facts,
                         fanout_graph_facts,
                         port_id,
                         lossless_prio,
                         start_delay_secs,
                         pause_line_rate,
                         traffic_duration,
                         traffic_line_rate,
                         frame_size,
                         test_flow_name,
                         ecn_thresholds,
                         outstanding_packets,
                         iteration_count,
                         ecn_max_pkt,
                         expected_min_marked_packets,
                         expected_max_marked_packets) :

    number_of_packets = int((ecn_thresholds / frame_size) + outstanding_packets)
    tgen_ports = TgenPorts(conn_graph_facts, fanout_graph_facts)
    port_list = tgen_ports.create_ports_list(2, port_id)
    l1_config = tgen_ports.l1_config(port_list)

    l1_config.layer1[0].port_names = ['Tx', 'Rx']
    l1_config.ports[0].name = 'Tx'
    l1_config.ports[1].name = 'Rx'

    base_config = __base_configs__(conn_graph_facts=conn_graph_facts,
                                   duthost=duthost,
                                   lossless_prio_dscp_map=lossless_prio,
                                   l1_config=l1_config,
                                   start_delay_secs=start_delay_secs,
                                   traffic_duration=traffic_duration,
                                   pause_line_rate=pause_line_rate,
                                   traffic_line_rate=traffic_line_rate,
                                   frame_size=frame_size,
                                   ecn_thresholds=ecn_thresholds,
                                   number_of_packets=number_of_packets,
                                   test_flow_name=test_flow_name)

    packet_marked_stats = [] 
    for i in range(iteration_count):
        rx_port=base_config.ports[1]
        base_config.captures.append(Capture(choice=[],
                                name='Rx Capture',
                                enable=True,
                                port_names=[rx_port.name]))

        # create the configuration
        api.set_state(State(ConfigState(config=base_config, state='set')))

        # start capture
        api.set_state(State(PortCaptureState(port_names=[rx_port.name], state='start')))

        # start all flows
        api.set_state(State(FlowTransmitState(state='start')))

        exp_dur = start_delay_secs + traffic_duration
        logger.info("Traffic is running for %s seconds" %(traffic_duration))
        time.sleep(exp_dur)

        # stop all flows
        api.set_state(State(FlowTransmitState(state='stop')))

        pcap_bytes = api.get_capture_results(CaptureRequest(port_name=rx_port.name))

        # Get statistics
        for row in api.get_flow_results(FlowRequest(flow_names=[test_flow_name])):
            if (row['name'] == test_flow_name) :
                if ((row['frames_rx'] == 0) or (row['frames_tx'] != row['frames_rx'])):
                     logger.error("Tx = %s Rx = %s" % (row['frames_tx'], row['frames_rx']))
                     pytest_assert(False, "Not all %s reached Rx End")

        # write the pcap bytes to a local file
        with open('%s.pcap' % rx_port.name, 'wb') as fid:
            fid.write(b'%s'%(pcap_bytes))

        from scapy.all import rdpcap
        reader = rdpcap('%s.pcap' % rx_port.name)

        ip_packet = filter(lambda x : x.haslayer('IP'), reader)

        marked_packet = 0
        # check OUTSTANDING_PACKETS must be marked
        for cntr in range(outstanding_packets): 
            # last 3 bits of tos must be b'11' i.e 3   
            if (ip_packet[cntr]['IP'].getfieldval('tos') & 3 == 3):
                marked_packet += 1
            else:
                pytest_assert(False, "First %s packets must be ECN marked"\
                   %(outstanding_packets)) 

        # check rest of the packets if they are marked
        for cntr in range(outstanding_packets, ecn_max_pkt):
            # last 3 bits of tos must be b'11' i.e 3   
            if (ip_packet[cntr]['IP'].getfieldval('tos') & 3 == 3):
                marked_packet += 1

        # count total number of marked packets
        if ((marked_packet <= expected_min_marked_packets) and
            (marked_packet > expected_max_marked_packets)):
            pytest_assert(False,
                "Expected nummer of matched ECN packets not found")
        else:
            packet_marked_stats.append(marked_packet)      

        logger.info("iteration = %s outstanding packets = %s marked = %s"\
            %(i + 1, outstanding_packets, marked_packet))

    # end iteration
    logger.info("Iteration\tpacket marked")
    logger.info("---------\t-------------")
    for i in range(ITERATION_COUNT):
        logger.info("%s\t\t%s" %(i,  packet_marked_stats[i]))
    
