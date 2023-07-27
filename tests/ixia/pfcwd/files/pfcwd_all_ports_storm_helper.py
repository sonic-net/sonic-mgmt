import os 
import time 
from math import ceil

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.ixia.ixia_helpers import get_dut_port_id
from tests.common.ixia.common_helpers import pfc_class_enable_vector,\
    start_pfcwd, enable_packet_aging, get_pfcwd_poll_interval, get_pfcwd_detect_time
from tests.common.ixia.port import select_ports

from abstract_open_traffic_generator.flow import TxRx, Flow, Header, Size, Rate
from abstract_open_traffic_generator.flow import Duration, Continuous, PortTxRx, PfcPause  
from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.control import State, ConfigState, FlowTransmitState
from abstract_open_traffic_generator.result import FlowRequest
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer 

PAUSE_FLOW_NAME = 'PauseStorm'
IXIA_POLL_DELAY_SEC = 2
TOLERANCE_THRESHOLD = 0.05

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")
EXPECT_PFC_WD_DETECT_RE = ".* detected PFC storm .*"
EXPECT_PFC_WD_RESTORE_RE = ".*storm restored.*" 


def run_pfcwd_pause_storm_test(api,
                               testbed_config,
                               port_config_list,
                               conn_data,
                               fanout_data,
                               duthost,
                               dut_ports_list,
                               pause_prio_list,
                               prio_dscp_map):  
    """
    Run PFC Pause Storm on all ports  

    Args:
        api (obj): IXIA session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        pause_prio_list (list): priorities to pause for PFC pause storm
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
    Returns:
        N/A
    """
    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')
    num_ports = len(port_config_list)
    pytest_require(num_ports >= 3, "This test requires at least 3 ports")

    start_pfcwd(duthost)
    enable_packet_aging(duthost)
    flows=[] 

    for dut_port in dut_ports_list: 
        """ Get the ID of the port to test """
        port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

        pytest_assert(port_id is not None,
                  'Fail to get ID for port {}'.format(dut_port))

        poll_interval_sec = get_pfcwd_poll_interval(duthost) / 1000.0
        detect_time_sec = get_pfcwd_detect_time(host_ans=duthost, intf=dut_port) / 1000.0

        pfc_storm_dur_sec = poll_interval_sec + detect_time_sec

        exp_dur_sec = ceil(pfc_storm_dur_sec + 1)

        """ Generate traffic config """

        flow_name=PAUSE_FLOW_NAME + str(port_id)  
        pause_flows = __gen_traffic(testbed_config=testbed_config,
                                    port_config_list=port_config_list,
                                    port_id=port_id,
                                    pause_flow_name=flow_name,
                                    pause_prio_list=pause_prio_list,
                                    pfc_storm_dur_sec=pfc_storm_dur_sec,
                                    prio_dscp_map=prio_dscp_map)  

        flows.extend(pause_flows) 

    """ Tgen config = testbed config + flow config """

    syslog_marker = "all_port_storm"  

    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=syslog_marker)

    loganalyzer.expect_regex = []

    for port in dut_ports_list: 
        expect_regex = [EXPECT_PFC_WD_DETECT_RE+port]  

        loganalyzer.expect_regex.extend(expect_regex)

    loganalyzer.match_regex = [] 

    time.sleep(15) 

    config = testbed_config
    config.flows = flows

    all_flow_names = [flow.name for flow in flows]

    with loganalyzer: 
        flow_stats = __run_traffic(api=api,
                                   config=config,
                                   all_flow_names=all_flow_names,
                                   exp_dur_sec=exp_dur_sec)

    time.sleep(10) 

    loganalyzer.expect_regex = [] 
    for port in dut_ports_list:

        expect_regex = [EXPECT_PFC_WD_RESTORE_RE+port]
        loganalyzer.expect_regex.extend(expect_regex)

    with loganalyzer: 
        flow_stats = __stop_traffic(api=api, config=config, all_flow_names=all_flow_names)  

        time.sleep(15) 

    if not flow_stats:
        pytest_assert('Fail to stop the traffic')

        
def __gen_traffic(testbed_config,
                  port_config_list,
                  port_id,
                  pause_flow_name,
                  pause_prio_list,
                  pfc_storm_dur_sec,
                  prio_dscp_map):  
    """
    Generate configurations of flows under all to all traffic pattern, including
    test flows, background flows and pause storm. Test flows and background flows
    are also known as data flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test.
        pause_flow_name (str): name of pause storm
        pause_prio_list (list): priorities to pause for PFC frames
        pfc_storm_dur_sec (float): duration of the pause storm in second
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        flows configurations (list)
    """
    result = list()

    """ Generate a PFC pause storm """
    pause_port_id = port_id
    pause_flow = __gen_pause_flow(testbed_config=testbed_config,
                                  port_config_list=port_config_list,
                                  src_port_id=pause_port_id,
                                  flow_name=pause_flow_name,
                                  pause_prio_list=pause_prio_list,
                                  flow_dur_sec=pfc_storm_dur_sec)

    result.append(pause_flow)

    return result


def __gen_pause_flow(testbed_config,
                     port_config_list,
                     src_port_id,
                     flow_name,
                     pause_prio_list,
                     flow_dur_sec):
    """
    Generate the configuration for a PFC pause storm

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        src_port_id (int): ID of the source port
        flow_name (str): flow' name
        pause_prio_list (list): priorities to pause for PFC frames
        flow_dur_sec (float): duration of the flow in second

    Returns:
        flow configuration (obj): including name, packet format, rate, ...
    """
    pause_time = []
    for x in range(8):
        if x in pause_prio_list:
            pause_time.append('ffff')
        else:
            pause_time.append('0000')

    vector = pfc_class_enable_vector(pause_prio_list)

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

    pause_src_point = PortTxRx(tx_port_name=testbed_config.ports[src_port_id].name,
                               rx_port_name=testbed_config.ports[src_port_id].name)

    """
    The minimal fixed time duration in IXIA is 1 second.
    To support smaller durations, we need to use # of packets
    """
    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])
    pause_dur = 65535 * 64 * 8.0 / (speed_gbps * 1e9)
    pps = int(2 / pause_dur)

    pause_flow = Flow(
        name=flow_name,
        tx_rx=TxRx(pause_src_point),
        packet=[pause_pkt],
        size=Size(64),
        rate=Rate('pps', value=pps),
        duration=Duration(Continuous(delay=0, delay_unit='nanoseconds'))
    )

    return pause_flow


def __run_traffic(api, config, all_flow_names, exp_dur_sec):
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


def __stop_traffic(api, config, all_flow_names): 

    """ Dump per-flow statistics """
    rows = api.get_flow_results(FlowRequest(flow_names=all_flow_names))
    api.set_state(State(FlowTransmitState(state='stop')))

    return rows
