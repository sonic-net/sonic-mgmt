from tests.common.tgen.tgen_helpers import *
from abstract_open_traffic_generator.device import *
from abstract_open_traffic_generator.flow import \
    Flow, TxRx, DeviceTxRx, Header, Size, Rate, Duration, \
    Continuous
from abstract_open_traffic_generator.flow_ipv4 import\
    Priority, Dscp
from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.result import FlowRequest
from abstract_open_traffic_generator.control import *
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from .utils import *
import logging
import pytest

logger = logging.getLogger(__name__)

""" Delay to start test Traffic """
START_DELAY = 1

""" Rate percentage of test traffic """
TRAFFIC_LINE_RATE = 50

""" Data packet size in bytes """
FRAME_SIZE = 1024

""" Traffic through put tolerance """
TOLERANCE_PERCENT = 1

""" 
    Hardcoding storm detection and restoration for 
    now, will fetch from the DUT once the code structure
    is approved.
"""
STORM_DETECTION_TIME = 400
STORM_RESTORATION_TIME = 2000

def run_pfcwd_impact_test(api, duthost, port_id, conn_graph_facts, fanout_graph_facts):

    """ runs the pfcwd impact test """ 
    
    __create_tgen_config__(api=api,
                           duthost=duthost,
                           port_id=port_id,
                           conn_graph_facts=conn_graph_facts,
                           fanout_graph_facts=fanout_graph_facts,
                           start_delay=START_DELAY,
                           traffic_line_rate=TRAFFIC_LINE_RATE,
                           frame_size=FRAME_SIZE)

    __run_pfcwd_impact_test__(api=api, duthost=duthost)



def __create_tgen_config__(api,
                           duthost,
                           port_id,
                           conn_graph_facts,
                           fanout_graph_facts,
                           start_delay,
                           traffic_line_rate,
                           frame_size):
    """ Creates the Tgen config """
    ######################################################################
    # TgenPorts object is used to retrive the port bandwidth information
    # dynamically from the DUT conn_graph_facts and fanout_graph_facts
    # this will help config the tgen port
    ######################################################################

    tgen_ports = TgenPorts(conn_graph_facts, fanout_graph_facts)
    # returns the list of current and neighboring ports information
    port_list = tgen_ports.create_ports_list(2, port_id)
    ######################################################################
    # Fetching lossless priority from duthost
    # testcase will configure all the lossless priorities in one traffic
    # item
    ######################################################################    
    lossless_priority = lossless_prio_dscp_map(duthost, True)

    ######################################################################
    # Tgen Device Configuration
    ######################################################################
    
    vlan_subnet = get_vlan_subnet(duthost)
    vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, len(port_list))
    gw_ip = vlan_subnet.split('/')[0]
    network_prefix = vlan_subnet.split('/')[1]

    tgen_config = tgen_ports.l1_config(port_list)

    tx_port = tgen_config.ports[0]
    rx_port = tgen_config.ports[1]

    tx_device = Device(name='Tx Device',
           device_count=1,
           choice=Ipv4(name='Tx Ipv4',
                       address=Pattern(vlan_ip_addrs[0]),
                       prefix=Pattern(network_prefix),
                       gateway=Pattern(gw_ip),
                       ethernet=Ethernet(name='Tx Ethernet')
                )
        )
    tx_port.devices = [tx_device]

    rx_device = Device(name='Rx Device',
           device_count=1,
           choice=Ipv4(name='Rx Ipv4',
                       address=Pattern(vlan_ip_addrs[1]),
                       prefix=Pattern(network_prefix),
                       gateway=Pattern(gw_ip),
                       ethernet=Ethernet(name='Rx Ethernet')
                )
        )
    rx_port.devices = [rx_device]

    ######################################################################
    # Fetching priorities for lossless and lossy traffic
    ######################################################################
    interface_priorities = lossless_priority[1]
    priority_lossless_list = lossless_priority[0]
    
    lossless_list = interface_priorities.get(port_list[0].get('peer_port'))
    if lossless_list is None:
        pytest_assert(False, "DSCP priorities are not configured on the port {}".format(port_list[0].get('peer_port')))

    final_lossless_list = []
    for dscp in lossless_list:
        if priority_lossless_list.get(dscp) is None:
            continue
        list_values = [str(x) for x in priority_lossless_list.get(dscp)]
        final_lossless_list = final_lossless_list + list_values
    
    dscp_prio_lossy = [str(x) for x in range(64) if str(x) not in final_lossless_list]
    
    ######################################################################
    # Traffic configuration Traffic 1->2 lossless
    ######################################################################
    
    dscp_prio = Priority(Dscp(phb=FieldPattern(choice=final_lossless_list)))
    flow_config = Flow(name="Traffic 1->2 lossless",
                       tx_rx=TxRx(DeviceTxRx(tx_device_names=[tx_device.name],rx_device_names=[rx_device.name])),
                       packet=[
                        Header(choice=EthernetHeader()),
                        Header(choice=Ipv4Header(priority=dscp_prio)),
                       ],
                       size=Size(FRAME_SIZE),
                       rate=Rate('line', TRAFFIC_LINE_RATE),
                       duration=Duration(Continuous(delay=START_DELAY, delay_unit='nanoseconds'))
                )
    tgen_config.flows.append(flow_config)

    ######################################################################
    # Traffic configuration Traffic 1->2 lossy
    ######################################################################
    
    dscp_prio = Priority(Dscp(phb=FieldPattern(choice=dscp_prio_lossy)))
    flow_config = Flow(name="Traffic 1->2 lossy",
                       tx_rx=TxRx(DeviceTxRx(tx_device_names=[tx_device.name],rx_device_names=[rx_device.name])),
                       packet=[
                        Header(choice=EthernetHeader()),
                        Header(choice=Ipv4Header(priority=dscp_prio)),
                       ],
                       size=Size(FRAME_SIZE),
                       rate=Rate('line', TRAFFIC_LINE_RATE),
                       duration=Duration(Continuous(delay=START_DELAY, delay_unit='nanoseconds'))
                )
    tgen_config.flows.append(flow_config)
    #######################################################################
    # Applying TGEN Config Created above and Test on lossless and lossy
    #######################################################################
    api.set_state(State(ConfigState(config=tgen_config, state='set')))


def __run_pfcwd_impact_test__(api, duthost):
    """ runs the impact test """
    #######################################################################
    # Saving the DUT Configuration in variables and disabling pfcwd
    #######################################################################

    dut_cmd_disable = 'sudo pfcwd stop'
    dut_cmd_enable = 'sudo pfcwd start --action drop ports all detection-time {} \
           --restoration-time {}'.format(STORM_DETECTION_TIME, STORM_RESTORATION_TIME)
    duthost.shell(dut_cmd_disable)
    duthost.shell('pfcwd show config')     

    ##############################################################################################
    # Start all flows 
    # 1. check for no loss in the flows Traffic 1->2 lossless,Traffic 1->2 lossy
    # 2. configure pfcwd on dut and wait for 5 seconds
    # 3. check for no loss in the flows configured
    ##############################################################################################
    logger.info("Starting the traffic")
    api.set_state(State(FlowTransmitState(state='start')))
    ##############################################################################################
    # Checking for the traffic state if it is started.
    ##############################################################################################
    __wait_for_traffic_start__(api)
    
    logger.info("STEP1: Verify the traffic, No loss Expected on all Priorities whild PFCWD is disabled")
    __verify_traffic_for_impact_test__(api, 0.0, 'disabled')
    logger.info("Sleeping for 5 seconds")
    time.sleep(5)
    logger.info("STEP2: Enabling PFCWD")
    duthost.shell(dut_cmd_enable)
    logger.info("STEP3: Verify the traffic, No loss Expected on all Priorities whild PFCWD is enabled")
    __verify_traffic_for_impact_test__(api, 0.0, 'enabled')
    logger.info("STEP4: Verify the traffic, No loss Expected on all Priorities whild PFCWD is disabled")
    duthost.shell(dut_cmd_disable)
    __verify_traffic_for_impact_test__(api, 0.0, 'disabled')
    
    logger.info("Stopping the traffic")
    api.set_state(State(FlowTransmitState(state='stop')))


def __wait_for_traffic_start__(api):
    """ Wait for the traffic to Start """
    for i in range(100):
        test_stat = api.get_flow_results(FlowRequest())
        if "started" in test_stat[0]['transmit']:
            break
        time.sleep(3)


def __verify_traffic_for_impact_test__(api, expected_loss, pfc_state):
    """ Verify the traffic loss and through put """
    test_stat = api.get_flow_results(FlowRequest())
    for flow in test_stat:
        if flow['loss'] > expected_loss:
            pytest.fail("Observing loss in the flow {} while pfcwd state {}"
                            .format(flow['name'],pfc_state))
        tx_frame_rate = int(flow['frames_tx_rate'])
        rx_frame_rate = int(flow['frames_rx_rate'])
        tolerance = (tx_frame_rate * TOLERANCE_PERCENT)/100
        logger.info("\nTx Frame Rate,Rx Frame Rate of {} is {},{}"
                    .format(flow['name'],tx_frame_rate,rx_frame_rate))
        if tx_frame_rate > (rx_frame_rate + tolerance):
            pytest.fail("Observing traffic rate change in the flow {} while pfcwd state {}"
                        .format(flow['name'],pfc_state))



    
    