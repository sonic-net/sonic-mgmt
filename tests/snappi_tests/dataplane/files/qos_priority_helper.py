import logging
import pytest
from re import search, match
import json
from tabulate import tabulate
import time
import itertools
import random
import pandas as pd

from tests.common.snappi_tests.snappi_helpers import get_dut_port_id
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.variables import pfcQueueGroupSize, pfcQueueValueDict
from tests.common.snappi_tests.common_helpers import sec_to_nanosec

logger = logging.getLogger(__name__)

def read_dut_configs(Common_vars, duthosts, typeOfTest='dwrr'): 
    """               
    Read all dut config_db configurations one-by-one to build a data structure for creating snappi traffic items
    """
    for dut in duthosts:
        # If traffic chassis's are chained, don't expect ports from multiple chassis's. 
        # Could be using ports from just one chassis.
        if dut.hostname not in Common_vars.snappi_port_groups.keys():
            return
    
        verify_dut_scheduler_obj = read_dut_qos_configurations(Common_vars, dut) 
        set_snappi_qos_traffic(Common_vars, dut, verify_dut_scheduler_obj, typeOfTest)

def read_dut_qos_configurations(Common_vars, duthost):
    """
    Read a Sonic DUT configurations.
    
    Read all the Ethernet#|# in QUEUE to collect in a list of all the unique queue IDs.
    Then get the weights for each queue and sum them up as total_weight
    Note: The Ethernet port in QUEUE could be configured for 3 queues or 5 queues or 10 queues.
          For example:
              All the queues from the ports: [0, 1, 3, 5, 7, 10, 15, 20, 23, 25, 27, 30, 31]
              Get the weights for each queue/scheduler.id
              The sum of weights is total_weight
              
          Current HW support 8 queues

    Consumed by the function set_snappi_qos_traffic() to dynamically create traffic flows.
    
    'sonic-s6100-dut1': {
        'scheduler': {'scheduler.0': '1', 'scheduler.1': '10', 'scheduler.2': '20', 'scheduler.3': '30'},
        'weight_list': [1, 10, 20, 30],
        'traffic_class_queue_id_map': {0: '0', 1: '1', 2: '2', 3: '3', 4: '4', 5: '5', 6: '6', 7: '7', 8: '8', 9: '9’}}
    }

    'queue_id_list': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    'dscp_tos_generator': {
            0: <generator object round_robin at 0x7fdd71f93350>,
            1: <generator object round_robin at 0x7fdd71fc9350>,
            2: <generator object round_robin at 0x7fdd7237a190>,
            3: <generator object round_robin at 0x7fdd7237df90>,
            4: <generator object round_robin at 0x7fdd7179b970>,
            5: <generator object round_robin at 0x7fdd713fa580>,
            6: <generator object round_robin at 0x7fdd713d3eb0>,
            7: <generator object round_robin at 0x7fdd713d3820>,
            8: <generator object round_robin at 0x7fdd727ce430>,
            9: <generator object round_robin at 0x7fdd73219d60>
        }
    """
    dut_hostname = duthost.hostname
    
    Common_vars.dut_qos_configs[dut_hostname] = {'scheduler': {}, 
                                                 'weight_list': [],
                                                 'traffic_class_queue_id_map': {}
                                                 }
    
    verify_dut_scheduler_str = duthost.shell("show runningconfiguration all")['stdout']
    verify_dut_scheduler_obj = json.loads(verify_dut_scheduler_str)
    
    # Check for required QoS KEYS in the dut's configuration  'PFC_WD',
    for config_db_key in ['BUFFER_POOL', 'BUFFER_PG',  'SCHEDULER', 'TC_TO_QUEUE_MAP',
                          'DSCP_TO_TC_MAP', 'TC_TO_PRIORITY_GROUP_MAP', 'QUEUE', 'WRED_PROFILE']:
        pytest_assert(config_db_key in verify_dut_scheduler_obj.keys(), f'{config_db_key} is required in config_db') 

    # TC_TO_QUEUE_MAP: Left_side is traffic_class. Right side is queue_id. 
    for traffic_class, queue_id in verify_dut_scheduler_obj['TC_TO_QUEUE_MAP']['AZURE'].items():
        Common_vars.dut_qos_configs[dut_hostname]['traffic_class_queue_id_map'][int(queue_id)] = traffic_class

    # Read QUEUE to create a list of all the used queue IDs
    """
     "QUEUE": {
        "Ethernet0|0": {
            "scheduler": "scheduler.0"
        }
    """    
    # Read just the rx-port to get a list of queue IDs
    for port_group_num, properties in Common_vars.snappi_port_groups[dut_hostname].items():
        for snappi_rx_port in properties['rx_ports']:
            snappi_peer_port_name = snappi_rx_port['peer_port']

            for interface in verify_dut_scheduler_obj['QUEUE'].keys():
                # For some reason, reading the dut inserts {i} to QUEUE interfaces -> Ethernet99|{i}
                if interface.split('|')[1] == '{i}':
                    continue
                
                eth_interface = interface.split('|')[0]
                
                if snappi_peer_port_name == eth_interface:
                    eth_interface_queue_id = int(interface.split('|')[1])
                    if snappi_rx_port['peer_port'] == eth_interface:
                        if int(eth_interface_queue_id) not in properties['queue_id_list']:
                            properties['queue_id_list'].append(eth_interface_queue_id)    

    # For each tx-port, calculate the total-weight
    # Total weight is all the tx-port active queue IDs
    for port_group_num, properties in Common_vars.snappi_port_groups[dut_hostname].items():
        for snappi_tx_port in properties['tx_ports']:
            snappi_peer_port_name = snappi_tx_port['peer_port']
            tx_port_queue_id_counter = 0
            
            for interface in verify_dut_scheduler_obj['QUEUE'].keys():
                eth_interface = interface.split('|')[0]
                
                # total_tx_ports should be 7 
                if snappi_peer_port_name == eth_interface and tx_port_queue_id_counter < Common_vars.total_tx_ports:
                    eth_interface_queue_id = int(interface.split('|')[1])
                    eth_interface_scheduler_id = verify_dut_scheduler_obj['QUEUE'][interface]['scheduler']
                    scheduler_id_weight = verify_dut_scheduler_obj['SCHEDULER'][eth_interface_scheduler_id]['weight']
                    snappi_tx_port['total_weight'] += int(scheduler_id_weight)        
                    tx_port_queue_id_counter += 1
                                        
    # Create a table for pfc queue associated with dscp value-list.
    # Use round robin generator to provide the next PHB value

    for port_group_num, properties in Common_vars.snappi_port_groups[dut_hostname].items():
        for queue_id in properties['queue_id_list']: 
            # There could be many DSCP values for a queue ID 
            dscp_value_list = [] 
            # Get mapping for the QUEUE ID to Traffic Class in DSCP_TO_TC_MAP
            traffic_class_value = Common_vars.dut_qos_configs[dut_hostname]['traffic_class_queue_id_map'][queue_id]
            
            for dscp_value, traffic_class in verify_dut_scheduler_obj['DSCP_TO_TC_MAP']['AZURE'].items():
                # For each queue_id/traffic_class, get all the dscp phb values
                if int(traffic_class_value) == int(traffic_class):
                    # The left column in DSCP_TO_TC_MAP is dscp value, the right column is traffic class.
                    # Based on the queue ID, use TC_TO_QUEUE_MAP to get queue_id by the traffic_class to get the dscp value for the tx-port?
                    dscp_value_list.append(dscp_value)
        
            '''
            These are user defined queue_id mappings to PHB values
            queue_id:0 dscp_values:['0', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '47', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '6', '60', '61', '62', '63']
            queue_id:1 dscp_values:['1']
            queue_id:2 dscp_values:['2']
            queue_id:3 dscp_values:['3']
            queue_id:4 dscp_values:['4']
            queue_id:5 dscp_values:['5']
            queue_id:6 dscp_values:['6']
            queue_id:7 dscp_values:['7']
            queue_id:8 dscp_values:['8']
            queue_id:9 dscp_values:['9']
            '''
            if len(dscp_value_list) > 0:
                # NOTE: Search for all pfc_queue (0-6) in DSCP_TO_TC_MAP.
                #       If the user did not configure any dscp value with one of the 0-6 pfc_queue, skip it  
                # TC_TO_QUEUE_MAP: right side is queue_id, left_side is traffic_class
                Common_vars.snappi_port_groups[dut_hostname][port_group_num]['dscp_tos_generator'].update({queue_id: round_robin(dscp_value_list)})

    # Get all the defined scheduler ID in the configuration
    for schedulerId, properties in verify_dut_scheduler_obj['SCHEDULER'].items():
        Common_vars.dut_qos_configs[dut_hostname]['scheduler'].update({schedulerId: properties['weight']})
        
        # Go through each port in "QUEUE" to get all its queue to add the scheduler's weight 
        Common_vars.dut_qos_configs[dut_hostname]['weight_list'].append(int(properties['weight']))
    
    return verify_dut_scheduler_obj        

def set_snappi_qos_traffic(Common_vars, duthost, verify_dut_scheduler_obj, typeOfTest):
    """
    This function reads one duthost configs.
    Create a dut_qos_configs dict of each dut_host containing its qos/pfc configs
    Create traffic flow list
    
    typeOfTest: Options: dwrr | dwrr+wred
    """
    dut_hostname = duthost.hostname

    # Configure in groups of 8 ports. 7 tx-ports and 1 rx-port. Rotate the list of ports to be the rx_port so 
    # every port is tested as a rx-port.  Create traffic items for each dut.

    """
    Example: Common_vars.dut_qos_configs:
    {
        'sonic-s6100-dut1': {
            'scheduler': {'scheduler.0': '5', 'scheduler.1': '15', 'scheduler.2': '20'},
            'weight_list': [5, 15, 20],
            'dscp_tos_generator': {
                0: <generator object round_robin at 0x7f6d7eb13d60>,
                1: <generator object round_robin at 0x7f6d7eb13040>,
                2: <generator object round_robin at 0x7f6d7eb13510>,
                3: <generator object round_robin at 0x7f6d7eb134a0>,
                4: <generator object round_robin at 0x7f6d7eb13350>,
                5: <generator object round_robin at 0x7f6d7eb133c0>,
                6: <generator object round_robin at 0x7f6d7eb13430>
            },
            'pfc_queue_id_generator': {
                'scheduler.0': <generator object round_robin at 0x7f6d7ec397b0>,
                'scheduler.1': <generator object round_robin at 0x7f6d7ec39740>,
                'scheduler.2': <generator object round_robin at 0x7f6d7ec396d0>
            }
        }
    }
    """
    for port_group_num, properties in Common_vars.snappi_port_groups[dut_hostname].items():
        # Each tx-port uses a unique queue ID
        queue_id_generator = round_robin(properties['queue_id_list'])
        
        # Each Tx-Port sends with a unique queue ID of the Rx Port
        for tx_port in properties['tx_ports']:
            tx_port_location    = tx_port['location']
            dut_port_name       = tx_port['peer_port']
            ip_address          = tx_port['ipAddress']
            src_mac_address     = tx_port['src_mac_address']
            router_mac_address  = tx_port['router_mac_address']

            # With the scheduler ID, get the next pfc queue ID (Reading "QUEUE" -> Ethernet#|2)
            #   pfc_queue_id_generator:  scheduler_id: round_robin(pfc_queue_list_with_same_scheduler_id)
            #       scheduler.0: ['0', '1', '2'] 
            #       scheduler.1: ['3', '4']      
            #       scheduler.2: ['5', '6']  
            #
            #          Ethernet0|0 scheduler.0
            #          Ethernet0|1 scheduler.0
            #          Ethernet0|2 scheduler.0
            #          Ethernet0|3 scheduler.1
            #          Ethernet0|4 scheduler.1 
            #          Ethernet0|5 scheduler.2
            #          Ethernet0|6 scheduler.2
            # Every port round robins a queue ID
            queue_id = next(queue_id_generator)
            
            if int(queue_id) not in Common_vars.snappi_port_groups[dut_hostname][port_group_num]['dscp_tos_generator'].keys():
                pytest_assert(False, f'Misconfiguration in the config_db file. queue_id {str(queue_id)} was not set in DSCP_TO_TC_MAP')
            
            traffic_class = Common_vars.dut_qos_configs[dut_hostname]['traffic_class_queue_id_map'][int(queue_id)]
            phb_value = int(next(Common_vars.snappi_port_groups[dut_hostname][port_group_num]['dscp_tos_generator'][queue_id]))
            # if phb_value in [3, 4]:
            #      pbh_value = [phb_value]
            
            ethernet_port_name_with_queue_id = f'{dut_port_name}|{queue_id}'
            # "Ethernet0|0": {
            #    "scheduler": "scheduler.0"
            
            port_queue_scheduler_id = verify_dut_scheduler_obj['QUEUE'][ethernet_port_name_with_queue_id]['scheduler']
            # Get the scheduler.# weight
            weight = int(Common_vars.dut_qos_configs[dut_hostname]['scheduler'][port_queue_scheduler_id])
            
            # Total weight is all the Tx-port active queue IDs
            total_weight = tx_port['total_weight']

            """
                "QUEUE": {
                    "Ethernet0|0": {
                        "scheduler": "scheduler.0"
                    },
                    "Ethernet0|1": {
                        "scheduler": "scheduler.0"
                    }
            """      
            
            if typeOfTest == 'dwrr':
                # Lossless is not supported by HW as of this writing. Running 8x100G breakout.  Commenting this out until HW supports lossless.       
                # if ethernet_port_name in verify_dut_scheduler_obj['QUEUE'].keys() and \
                #     'wred_profile' in verify_dut_scheduler_obj['QUEUE'][ethernet_port_name] and \
                #     verify_dut_scheduler_obj['QUEUE'][ethernet_port_name]['wred_profile'] == 'AZURE_LOSSLESS':
                #     
                #     expected_loss_pct = 0.0
                # else:
                #     expected_loss_pct = calculate_traffic_loss_percentage(duthost=duthost, weight=weight, total_weight=total_weight)
                expected_loss_pct = calculate_traffic_loss_percentage(duthost=duthost,
                                                                      weight=weight,
                                                                      total_weight=total_weight)
            elif typeOfTest == 'dwrr+wred':
                expected_loss_pct = (100 - int(weight))
                 
            # NOTE: Use only one space in between words because verifying stats does a split(' ')[6]
            traffic_item_name = f'{dut_hostname}:{dut_port_name} SrcIp:{ip_address} QID:{queue_id} TC:{traffic_class} DSCP:{phb_value} {port_queue_scheduler_id} WT:{weight} TTl_WT:{total_weight} Expected_Loss%:{expected_loss_pct}'       
            logger.info(f'traffic_item: {traffic_item_name}')
            
            properties['traffic_items'].append({'traffic_item_name': traffic_item_name,
                                                'pfc_queue_id': queue_id,
                                                'dscp_phb_value': phb_value,
                                                'ip_address': ip_address,
                                                'router_mac_address': router_mac_address,
                                                'src_mac_address': src_mac_address,
                                                'location': tx_port_location,
                                                'dut_hostname': dut_hostname,
                                                'peer_port': dut_port_name
                                                })
            
            if hasattr(Common_vars, 'dut_queue_stat_counters'):
                if queue_id not in Common_vars.dut_queue_stat_counters:
                    Common_vars.dut_queue_stat_counters.append(queue_id)
                   
def round_robin(value_list):
    """ 
    A generator to get the next item on the list and 
    round robin back to the first item
    """
    pool = tuple(value_list)
    total_items = len(pool)
    indices = itertools.cycle(range(total_items))
    while True:
        yield pool[next(indices)]

def calculate_traffic_loss_percentage(duthost, weight: int, total_weight) -> int:
    """
    total_weight: The sum of RxPort "QUEUE" port mapping to the scheduler.id
    
    framesize: 4096
    
    step 1: Get allocated bandwidth to queue
     
       weight
    ------------  x 100 = allocated bandwidth to queue
    total weight
    
    step 2: Total bandwidth - allocated-bandwidth-to-queue = expected loss %
    
    Example:
        If weight = 15 and total weight = 40 (5, 15, 20) <-- If there were only 3 txPorts. Get their scheduler.id weights
        
        5/40 = 0.125 x 100 = 12.5 (allocated to queue)
        100 - 12.5 = 87.5% loss
    """
    pct_allocated_to_queue = (weight / total_weight) * 100
    expected_loss_pct = 100 - pct_allocated_to_queue

    # weight:15 total_weight:43  pct_allocated:34.883720930232556  expected_loss:65.11627906976744 float:65.1
    return round(float(expected_loss_pct), 1)

def create_packet_header(snappi_api, traffic_item_obj, packetHeaderProtocolTemplate, packetHeaderToAdd=None, appendToStack=None): 
    configElement = traffic_item_obj.ConfigElement.find()[0]

    # Append the <new packet header> object after the specified packet header stack.
    appendToStackObj = configElement.Stack.find(StackTypeId=appendToStack)
    appendToStackObj.Append(Arg2=packetHeaderProtocolTemplate)

    # Get the new packet header stack to use it for appending an IPv4 stack after it.
    # Look for the packet header object and stack ID.
    packetHeaderStackObj = configElement.Stack.find(StackTypeId=packetHeaderToAdd)
    
    # In order to modify the fields, get the field object and return it for usage
    packetHeaderFieldObj = packetHeaderStackObj.Field.find()

    return packetHeaderFieldObj

def create_snappi_flows(Common_vars, duthosts, config, snappi_api, snappi_port_configs):
    """
    Creating a many-to-one traffic pattern
    """

    # Configure Traffic Items
    # Currently, Snappi cannot reconfigure/recreate/remove traffic items.  Using Respy until Snappi issue is resolved.
    '''                             
    for port_group_num, properties in Common_vars.snappi_port_groups[dut_hostname].items():
        for tx_port in properties['traffic_items']:
            # tx_port: {'traffic_item_name': 'sonic-s6100-dut1:Ethernet16|0 scheduler.0 Weight:5 phb:8 87.5% loss', 
            # 'pfc_queue_id': 0, 'dscp_phb_value': 8, 'ip_address': '192.168.1.4', 'src_mac_address': 'aa:00:00:00:00:01', 
            # 'location': '10.36.84.33/2', 'dut_hostname': 'sonic-s6100-dut1'}
            dut_hostname = tx_port['dut_hostname']
            rx_port_details = properties['rx_ports'][0]
            
            flow = config.flows.flow(name=tx_port['traffic_item_name'])[-1]
            flow.tx_rx.port.tx_name = tx_port['location']
            flow.tx_rx.port.rx_name = rx_port_details['location']
            eth, ipv4 = flow.packet.ethernet().ipv4()
            eth.src.value = tx_port['src_mac_address']
            eth.dst.value = rx_port_details['src_mac_address']
            
            if pfcQueueGroupSize == 8:
                eth.pfc_queue.value = tx_port['pfc_queue_id']
            else:
                eth.pfc_queue.value = pfcQueueValueDict[tx_port['pfc_queue_id']]  

            ipv4.src.value = tx_port['ip_address']
            ipv4.dst.value = rx_port_details['ipAddress']
            ipv4.priority.choice = ipv4.priority.DSCP
            
            if type(tx_port['dscp_phb_value']) is list:
                ipv4.priority.dscp.phb.values = tx_port['dscp_phb_value']
            else:
                ipv4.priority.dscp.phb.value = tx_port['dscp_phb_value']
                
            ipv4.priority.dscp.ecn.value = (
                ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

            flow_delay_sec = 0
            flow.size.fixed = Common_vars.frame_size
            flow.rate.percentage = Common_vars.line_rate_percentage
            flow.duration.fixed_seconds.seconds = Common_vars.flow_duration_seconds
            flow.duration.fixed_seconds.delay.nanoseconds = int(sec_to_nanosec(flow_delay_sec))
            flow.metrics.enable = True
            flow.metrics.loss = True  
    '''
    if Common_vars.snappi_vports is None:
        Common_vars.snappi_vports = snappi_api._ixnetwork.Vport.find()

    packetHeaderProtocolTemplate = snappi_api._ixnetwork.Traffic.ProtocolTemplate.find(StackTypeId='ipv4') 

    for dut_host in duthosts: 
        if dut_host.hostname not in Common_vars.snappi_port_groups.keys():
            continue
                  
        for port_group_num, properties in Common_vars.snappi_port_groups[dut_host.hostname].items():
            for index, tx_port in enumerate(properties['traffic_items']):
                # tx_port: {'traffic_item_name': 'sonic-s6100-dut1:Ethernet16|0 scheduler.0 Weight:5 phb:8 87.5% loss', 
                #           'pfc_queue_id': 0, 'dscp_phb_value': 8, 'ip_address': '192.168.1.4', 'src_mac_address': 'aa:00:00:00:00:01', 
                #           'location': '10.36.84.33/2', 'dut_hostname': 'sonic-s6100-dut1', 'peer_port': 'Ethernet0'}
                rx_port_details = properties['rx_ports'][0]
                
                for vport in Common_vars.snappi_vports:
                    if vport.Location == rx_port_details['location']:
                        rx_port_vport = vport

                    if vport.Location == tx_port['location']:
                        tx_port_vport = vport
                        
                flowObj = snappi_api._ixnetwork.Traffic.TrafficItem.add(Name=tx_port['traffic_item_name'], BiDirectional=False)
                flowObj.EndpointSet.add(Sources=tx_port_vport.Protocols.find(), Destinations=rx_port_vport.Protocols.find())
                flowObj.Tracking.find()[0].TrackBy = ['trackingenabled0']
                configElement = flowObj.ConfigElement.find()[0]
                configElement.FrameRate.update(Type='percentLineRate', Rate=Common_vars.line_rate_percentage)
                
                flow_delay_sec = 0
                configElement.TransmissionControl.update(Type='continuous', Duration=Common_vars.flow_duration_seconds, StartDelay=int(sec_to_nanosec(flow_delay_sec)))
                configElement.FrameSize.FixedSize = Common_vars.frame_size

                ethernetStackObj = snappi_api._ixnetwork.Traffic.TrafficItem.find(Name=tx_port['traffic_item_name']).ConfigElement.find()[0].Stack.find(StackTypeId='ethernet$')
                ethernetDstField = ethernetStackObj.Field.find(DisplayName='Destination MAC Address')
                ethernetDstField.ValueType = 'singleValue'
                ethernetDstField.SingleValue = tx_port['router_mac_address']

                ethernetSrcField = ethernetStackObj.Field.find(DisplayName='Source MAC Address')
                ethernetSrcField.ValueType = 'singleValue'
                ethernetSrcField.SingleValue = tx_port['src_mac_address']
        
                pfcQueueObj = ethernetStackObj.Field.find(DisplayName='PFC Queue')
                pfcQueueObj.ValueType = 'singleValue'
                if pfcQueueGroupSize == 8:
                    pfcQueueObj.SingleValue = tx_port['pfc_queue_id']
                else:  
                    pfcQueueObj.SingleValue = pfcQueueValueDict[tx_port['pfc_queue_id']]
                
                ipv4FieldObj = create_packet_header(snappi_api, flowObj, packetHeaderProtocolTemplate, packetHeaderToAdd='ipv4', appendToStack='ethernet$')
                
                ipv4SrcField = ipv4FieldObj.find(DisplayName='Source Address')
                ipv4SrcField.ValueType = 'singleValue'
                ipv4SrcField.SingleValue = tx_port['ip_address']

                ipv4DstField = ipv4FieldObj.find(DisplayName='Destination Address')
                ipv4DstField.ValueType = 'singleValue'
                ipv4DstField.SingleValue = rx_port_details['ipAddress']

                # DSCP configurations and references
                ipv4PrecedenceField = ipv4FieldObj.find(DisplayName='Class selector PHB')
                ipv4PrecedenceField.ActiveFieldChoice = True
                ipv4PrecedenceField.ValueType = 'singleValue'
                ipv4PrecedenceField.SingleValue = tx_port['dscp_phb_value']

                # For WRED testing.  Set Unused field bit to 2 for marking ECN packets.
                ipv4PrecedenceField.find('Unused').find(FieldTypeId="ipv4.header.priority.ds.phb.classSelectorPHB.unused").ActiveFieldChoice = True
                ipv4PrecedenceField.find('Unused').find(FieldTypeId="ipv4.header.priority.ds.phb.classSelectorPHB.unused").ValueType = 'singleValue'
                ipv4PrecedenceField.find('Unused').find(FieldTypeId="ipv4.header.priority.ds.phb.classSelectorPHB.unused").SingleValue = 2
                                        
                logger.info(f'Creating Flow: Port-Group-{port_group_num} srcPort:{ tx_port["location"]} -> dstPort:{rx_port_details["location"]}   srcIp{tx_port["ip_address"]} -> dstIp{rx_port_details["ipAddress"]} DSCP:{tx_port["dscp_phb_value"]} QID:{tx_port["pfc_queue_id"]}')

    return config

def clear_dut_stat_counters(duthosts):               
    for dut_host in duthosts:
        logger.info(f'Clearing DUT stat counters: {dut_host.hostname}')

        logger.info('counterpoll wredqueue enable')
        dut_host.shell("counterpoll wredqueue enable")
        
        # for queue_id in Common_vars.dut_queue_stat_counters:
        #     logger.info(f'sudo ecnconfig -q {queue_id} on')
        #     dut_host.shell(f"sudo ecnconfig -q {queue_id} on")
                
        logger.info('sonic-clear queue wredcounters')
        dut_host.shell("sonic-clear queue wredcounters")    
                
def run_traffic(Common_vars, api, config):
    """
    Run traffic and dump per-flow statistics

    Args:
        api (obj): SNAPPI session
        config (obj): experiment config (testbed config + flow config)
        all_flow_names (list): list of names of all the flows
        exp_dur_sec (int): experiment duration in second

    Returns:
        per-flow statistics (list)
    """
    logger.info('Starting transmit on all flows ...')
    control_state = api.control_state()
    control_state.choice = control_state.TRAFFIC
    control_state.traffic.choice = control_state.traffic.FLOW_TRANSMIT
    control_state.traffic.flow_transmit.state = control_state.traffic.flow_transmit.START
    res = api.set_control_state(control_state)
    if len(res.warnings) > 0:
        # ['IxNet - PFC queue ID is adjusted from the configured value: 4 to the maximum supported value: 3', 
        #  'IxNet - PFC queue ID is adjusted from the configured value: 5 to the maximum supported value: 3', 
        #  'IxNet - PFC queue ID is adjusted from the configured value: 6 to the maximum supported value: 3']
        logger.warn(res.warnings)

    logger.info(f'Sleep {Common_vars.flow_duration_seconds} seconds ...')
    time.sleep(Common_vars.flow_duration_seconds)
    logger.info('Stop transmit on all flows ...')
    control_state.traffic.flow_transmit.state = control_state.traffic.flow_transmit.STOP
    res = api.set_control_state(control_state)
    time.sleep(5)

def get_flow_statistics(snappi_api, stat_view_name, stat_view_columns, show_tabulated_table=False):
    """
    snappi_api:           IxNetwork RestPy session object 
    stat_view_name:       IxNetwork stat view name: "Traffic Items", "Flow Statistics", "Port Statistics"
    stat_view_columns:    The stat view column names to get
    show_tabulated_table: Display flows in tabulated table
    """
    flow_stats = snappi_api._assistant.StatViewAssistant(stat_view_name)
    if len(flow_stats.Rows.RawData) == 0:
        pytest_assert(False, 'get_flow_statistics: No flow stats available')

    flow_stat_column_headers = flow_stats.ColumnHeaders

    if flow_stat_column_headers[0] == 'Gap':
        flow_stat_column_headers.pop(0)
  
    data_frame = pd.DataFrame(flow_stats.Rows.RawData, columns=flow_stat_column_headers)
    data_frame_selected = data_frame[stat_view_columns] 
    
    if show_tabulated_table:
        logger.info(f"\n{tabulate(data_frame_selected, headers='keys', tablefmt='pretty', numalign='right', stralign='left', colalign=('left', 'left', 'left'))}")

    return data_frame_selected.to_dict(orient="records") 

def delete_flows(snappi_api):
    logger.info('Removing flow configurations ...')
    for traffic_item in snappi_api._ixnetwork.Traffic.TrafficItem.find():
        traffic_item.remove()
        
def delete_flows_2(duthosts, snappi_api):
    """ 
    This function is not in used yet, but this will be used when snappi
    is able to recreate flows and configure packet headers
    """
    delete_traffic_items = []
    
    for dut_host in duthosts:
        dut_hostname = dut_host.hostname
        if dut_hostname not in Common_vars.snappi_port_groups.keys():
            continue
        
        for port_group_num, properties in Common_vars.snappi_port_groups[dut_hostname].items():
            for tx_port in properties['traffic_items']:
                delete_traffic_items.append(tx_port['traffic_item_name'])
        
    cd = snappi_api.config_delete()
    cd.config_delete_list.add().flows = delete_traffic_items
    logger.info(f"delete_flows: {cd}")
    snappi_api.delete_config(cd)
      
