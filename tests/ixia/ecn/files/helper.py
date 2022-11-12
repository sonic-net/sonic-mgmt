import time
import dpkt

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api
from tests.common.ixia.ixia_helpers import get_dut_port_id
from tests.common.ixia.common_helpers import pfc_class_enable_vector, config_wred,\
    enable_ecn, config_ingress_lossless_buffer_alpha, stop_pfcwd, disable_packet_aging
from tests.common.ixia.port import select_ports

from abstract_open_traffic_generator.capture import CustomFilter, Capture,\
    BasicFilter
from abstract_open_traffic_generator.flow import TxRx, Flow, Header,Size, Rate,\
    Duration, FixedSeconds, FixedPackets, PortTxRx, PfcPause
from abstract_open_traffic_generator.flow_ipv4 import Priority, Dscp
from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.control import State, ConfigState,\
    FlowTransmitState, PortCaptureState
from abstract_open_traffic_generator.result import FlowRequest, CaptureRequest

EXP_DURATION_SEC = 1
DATA_START_DELAY_SEC = 0.1
IXIA_POLL_DELAY_SEC = 2
PAUSE_FLOW_NAME = 'Pause Storm'
DATA_FLOW_NAME = 'Data Flow'
NUMBER_OF_TEST_PACKETS = 2100

sec_to_nanosec = lambda x : x * 1e9

def run_ecn_test(api,
                 testbed_config,
                 port_config_list,
                 conn_data,
                 fanout_data,
                 duthost,
                 dut_port,
                 kmin,
                 kmax,
                 pmax,
                 data_pkt_size,
                 lossless_prio,
                 prio_dscp_map,
                 iters,
                 data_pkt_cnt=NUMBER_OF_TEST_PACKETS,
                 xoff_quanta=65535,
                 data_traffic_rate=None,
                 number_of_transmit_ports=1,
                 pfc_storm_start_delay=0,
                 pfc_pkt_count=0,
                 enable_capture=True):
    """
    Run a ECN test

    Args:
        api (obj): IXIA session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        kmin (int): RED/ECN minimum threshold in bytes
        kmax (int): RED/ECN maximum threshold in bytes
        pmax (int): RED/ECN maximum marking probability in percentage
        data_pkt_size (int): data packet size in bytes
        data_pkt_cnt (int): data packet count, Default:2100, will be superseded by data_traffic_rate if data_traffic_rate is set.
        lossless_prio (int): lossless priority
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        iters (int): # of iterations in the test
        xoff_quanta: Value of xoff Quanta to use(default: 65535).
        data_traffic_rate: Rate of traffic instead of pkt_count. Supersedes pkt_count. This also disables capture config for now.
        number_of_transmit_ports: How many ports should we start the traffic from. Default:1 (one-to-one).
        pfc_storm_start_delay: The delay in microseconds before pause frames can be started.
        pfc_pkt_count: Count of pfc packets to send. 0 means continuous. Default: 0. 
        enable_capture: Should we capture packets on the receive port ? Avoid setting this flag along with data_traffic_rate to avoid overwhelming the ixia memory.

    Returns:
        Return captured IP packets (list of list)
        TODO: After the ixia support for counting the ECN marked packets is available,
        we can add the API call for the same, and obtain the number of ECN marked packets
        received in the RX Port.
    """

    pytest_assert(testbed_config is not None, 'Failed to get L2/3 testbed config')

    stop_pfcwd(duthost)
    disable_packet_aging(duthost)

    """ Configure WRED/ECN thresholds """
    config_result = config_wred(host_ans=duthost,
                                kmin=kmin,
                                kmax=kmax,
                                pmax=pmax)
    pytest_assert(config_result is True, 'Failed to configure WRED/ECN at the DUT')

    """ Enable ECN marking """
    enable_ecn(host_ans=duthost, prio=lossless_prio)

    """ Configure PFC threshold to 2 ^ 3 """
    config_result = config_ingress_lossless_buffer_alpha(host_ans=duthost,
                                                         alpha_log2=3)

    pytest_assert(config_result is True, 'Failed to configure PFC threshold to 8')

    """ Get the ID of the port to test """
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Failed to get ID for port {}'.format(dut_port))

    capture_config = None
    if enable_capture:
        """ Generate packet capture config """
        capture_config = __config_capture_ip_pkt(testbed_config=testbed_config, port_id=port_id)

    name_options = {}
    name_options['data_flow_names'] = []
    if number_of_transmit_ports == 1:
        name_options['data_flow_names'] = [DATA_FLOW_NAME]
    else:
        for i in range(number_of_transmit_ports):
            name_options['data_flow_names'].append(DATA_FLOW_NAME + " " + str(i+1))
    """ Generate traffic config """
    flows = __gen_traffic(testbed_config=testbed_config,
                          port_config_list=port_config_list,
                          port_id=port_id,
                          pause_flow_name=PAUSE_FLOW_NAME,
                          prio=lossless_prio,
                          data_pkt_size=data_pkt_size,
                          data_pkt_cnt=data_pkt_cnt,
                          data_flow_delay_sec=DATA_START_DELAY_SEC,
                          exp_dur_sec=EXP_DURATION_SEC,
                          prio_dscp_map=prio_dscp_map,
                          xoff_quanta=xoff_quanta,
                          data_traffic_rate=data_traffic_rate,
                          pfc_storm_start_delay=pfc_storm_start_delay,
                          pfc_pkt_count=pfc_pkt_count,
                          **name_options)

    """ Tgen config = testbed config + flow config + capture config"""
    config = testbed_config
    config.flows = flows
    if capture_config:
        config.captures = capture_config
        capture_port_name = capture_config[0].port_names[0]

    """ Run traffic and capture packets or get counters(if available). """
    result = []

    for i in range(iters):
        options = {}
        if capture_config:
            pcap_file_name = '{}-{}.pcap'.format(capture_port_name, i)
            options['capture_port_name'] = capture_port_name
            options['pcap_file_name'] = pcap_file_name

        __run_traffic(api=api,
                      config=config,
                      all_flow_names=[PAUSE_FLOW_NAME, DATA_FLOW_NAME],
                      exp_dur_sec=EXP_DURATION_SEC,
                      **options)

        if capture_config:
            result.append(__get_ip_pkts(pcap_file_name))

    return result

sec_to_nanosec = lambda x : x * 1e9

def __gen_traffic(testbed_config,
                  port_config_list,
                  port_id,
                  pause_flow_name,
                  data_flow_names,
                  prio,
                  data_pkt_size,
                  data_flow_delay_sec,
                  exp_dur_sec,
                  prio_dscp_map,
                  data_pkt_cnt=2100,
                  xoff_quanta=65535,
                  data_traffic_rate=None,
                  pfc_storm_start_delay=0,
                  pfc_pkt_count=0):

    """
    Generate configurations of flows, including a data flow and a PFC pause storm.
    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test
        pause_flow_name (str): name of the pause storm
        data_flow_names (list): List of names of the data flows
        prio (int): priority of the data flow and PFC pause storm
        data_pkt_size (int): packet size of the data flow in byte
        data_pkt_cnt (int): # of packets of the data flow
        data_flow_delay_sec (float): start delay of the data flow in second
        exp_dur_sec (float): experiment duration in second
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        xoff_quanta (int): Xoff quanta to use for xoff packets. Default 65535.
        data_traffic_rate (int): Rate of traffic in percentage line rate. Default 100.
        pfc_storm_start_delay (int): milliseconds delay for pause frame. Default:0(No delay).
        pfc_pkt_count: Number of pfc packets to send. 0 means continuous. Default:0
    Returns:
        Configurations of the data flow and the PFC pause storm (list)
    """
    result = list()

    rx_port_id = port_id
    tx_port_id_list, rx_port_id_list = select_ports(port_config_list=port_config_list,
                                                    pattern="many to one",
                                                    rx_port_id=rx_port_id)
    pytest_assert(len(tx_port_id_list) > 0, "Cannot find any TX ports")
    # Every port other than rx_port is a potential tx port now ;)
    tx_port_id_list = [x for x in tx_port_id_list if x != rx_port_id]
    pytest_assert(tx_port_id_list != [], "Cannot find a suitable TX port")

    tx_port_config_list = []
    rx_port_config = next((x for x in port_config_list if x.id == rx_port_id), None)
    for tx_port_id in tx_port_id_list:
        tx_port_config_list.append((next((x for x in port_config_list if x.id == tx_port_id), None)))

    number_of_tx_ports = len(tx_port_config_list)
    for index in range(len(data_flow_names)):
        tx_port_config = tx_port_config_list[index % number_of_tx_ports]
        tx_port_id = tx_port_id_list[index % number_of_tx_ports]

        tx_mac = tx_port_config.mac
        if tx_port_config.gateway == rx_port_config.gateway and \
           tx_port_config.prefix_len == rx_port_config.prefix_len:
            """ If soruce and destination port are in the same subnet """
            rx_mac = rx_port_config.mac
        else:
            rx_mac = tx_port_config.gateway_mac

        data_endpoint = PortTxRx(tx_port_name=testbed_config.ports[tx_port_id].name,
                                 rx_port_name=testbed_config.ports[rx_port_id].name)

        data_flow_delay_nanosec = sec_to_nanosec(data_flow_delay_sec)

        eth_hdr = EthernetHeader(src=FieldPattern(tx_mac),
                                dst=FieldPattern(rx_mac),
                                pfc_queue=FieldPattern([prio]))

        ip_prio = Priority(Dscp(phb=FieldPattern(choice=prio_dscp_map[prio]),
                                ecn=FieldPattern(choice=Dscp.ECN_CAPABLE_TRANSPORT_1)))
        ipv4_hdr = Ipv4Header(src=FieldPattern(tx_port_config.ip),
                              dst=FieldPattern(rx_port_config.ip),
                              priority=ip_prio)
        duration = {}
        if data_traffic_rate:
            duration['duration'] = Duration(FixedSeconds(seconds=exp_dur_sec,
                                           delay=0,
                                           delay_unit='nanoseconds'))
        else:
            duration['duration'] = Duration(FixedPackets(packets=data_pkt_cnt,
                                           delay=data_flow_delay_nanosec,
                                           delay_unit='nanoseconds'))

        data_flow = Flow(
            name=data_flow_names[index],
            tx_rx=TxRx(data_endpoint),
            packet=[Header(choice=eth_hdr), Header(choice=ipv4_hdr)],
            size=Size(data_pkt_size),
            rate=Rate('line', (data_traffic_rate or 51)),
            **duration
           )

        result.append(data_flow)

    """ PFC Pause Storm """
    pause_time = []
    for x in range(8):
        if x == prio:
            pause_time.append(hex(xoff_quanta).split('x')[-1])
        else:
            pause_time.append('0000')

    vector = pfc_class_enable_vector([prio])
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

    """ Pause frames are sent from the RX port """
    pause_endpoint = PortTxRx(tx_port_name=testbed_config.ports[rx_port_id].name,
                              rx_port_name=testbed_config.ports[tx_port_id].name)

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])
    pause_dur = xoff_quanta * 64 * 8.0 / (speed_gbps * 1e9)
    pps = int(2 / pause_dur)

    if pfc_pkt_count:
        pause_flow = Flow(name=pause_flow_name,
                          tx_rx=TxRx(pause_endpoint),
                          packet=[pause_pkt],
                          size=Size(64),
                          rate=Rate('pps', value=pps),
                          duration=Duration(FixedPackets(packets=pfc_pkt_count,
                                            delay=pfc_storm_start_delay,
                                            delay_unit='nanoseconds')))
    else:
        pause_flow = Flow(name=pause_flow_name,
                          tx_rx=TxRx(pause_endpoint),
                          packet=[pause_pkt],
                          size=Size(64),
                          rate=Rate('pps', value=pps),
                          duration=Duration(FixedSeconds(seconds=exp_dur_sec,
                                            delay=pfc_storm_start_delay,
                                            delay_unit='nanoseconds')))
    result.append(pause_flow)

    return result

def __config_capture_ip_pkt(testbed_config, port_id):
    """
    Generate the configuration to capture IP packets

    Args:
        testbed_config (obj): L2/L3 config of a T0 testbed
        port_id (int): ID of DUT port to capture packets

    Returns:
        Packet capture configuration (list)
    """

    """ We only capture IP packets """
    ip_filter = CustomFilter(filter='40', mask='0f', offset=14)
    result = [Capture(name='rx_capture',
                      port_names=[testbed_config.ports[port_id].name],
                      choice=[BasicFilter(ip_filter)],
                      enable=True)]
    return result

def __run_traffic(api,
                  config,
                  all_flow_names,
                  exp_dur_sec,
                  capture_port_name=None,
                  pcap_file_name=None):
    """
    Run traffic and capture packets

    Args:
        api (obj): IXIA session
        config (obj): experiment config
        all_flow_names (list): names of all the flows
        capture_port_name (str): name of the port to capture packets
        pcap_file_name (str): name of the pcap file to store captured packets

    Returns:
        N/A
    """
    api.set_state(State(ConfigState(config=config, state='set')))

    if capture_port_name:
        api.set_state(State(PortCaptureState(port_names=[capture_port_name],
                                         state='start')))

    api.set_state(State(FlowTransmitState(state='start')))
    time.sleep(exp_dur_sec)

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

    if capture_port_name:
        """ Dump captured packets """
        pcap_bytes = api.get_capture_results(CaptureRequest(port_name=capture_port_name))
        with open(pcap_file_name, 'wb') as fid:
            fid.write(pcap_bytes)

    """ Stop all the flows """
    api.set_state(State(FlowTransmitState(state='stop')))

def __get_ip_pkts(pcap_file_name):
    """
    Get IP packets from the pcap file

    Args:
        pcap_file_name (str): name of the pcap file to store captured packets

    Returns:
        Captured IP packets (list)
    """

    ip_pkts = []
    for ts, pkt in dpkt.pcap.Reader(open(pcap_file_name, 'rb')):
        eth = dpkt.ethernet.Ethernet(pkt)
        if isinstance(eth.data, dpkt.ip.IP):
            ip_pkts.append(eth.data)

    return ip_pkts

def is_ecn_marked(ip_pkt):
    """
    Determine if an IP packet is ECN marked

    Args:
        ip_pkt (obj): IP packet

    Returns:
        Return if the packet is ECN marked (bool)
    """

    return (ip_pkt.tos & 3) == 3
