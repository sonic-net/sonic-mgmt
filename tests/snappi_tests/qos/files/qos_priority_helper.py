import logging
from re import search, match
import json
from tabulate import tabulate
import time
import itertools
import pandas as pd
import traceback
from time import sleep
# from rich import print as pr

from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.common_helpers import sec_to_nanosec

logger = logging.getLogger(__name__)


def initiate_snappi_port_groups_dict(Common_vars, duthosts, snappi_port_configs):
    """
    Get all the user defined ports for the test.
    Note: Ports are not neccessarily in the order of 1,2,3,4.  It could be scattered 1,3,5,7.
    """
    # Get unique port-group list from snappi port locations
    for duthost in duthosts:
        Common_vars.snappi_port_groups[duthost.hostname] = {}
        Common_vars.port_group_range[duthost.hostname] = []

        for index, snappi_port in enumerate(snappi_port_configs):
            # snappi_port: snappi_port: {'ipAddress': '192.168.1.9', 'ipGateway': '192.168.1.3', 'prefix': 24,
            # 'subnet': '192.168.1.0/24', 'src_mac_address': 'aa:00:00:00:00:07',
            # 'router_mac_address': '9c:69:ed:6f:92:f1', 'speed': '100000',
            # 'snappi_speed_type': 'speed_100_gbps', 'peer_port': 'Ethernet7', 'location': '10.36.84.34/1.8',
            # 'duthost': <MultiAsicSonicHost sonic-s6100-dut1>, 'api_server_ip': '10.36.84.36',
            # 'asic_type': 'broadcom', 'asic_value': None, 'port_id': '8', 'fec': True, 'autoneg': False}
            snappi_port.update({'topology_group_index': index})

            if snappi_port['duthost'].hostname == duthost.hostname:
                location = snappi_port['location']
                # ['10.36.84.33', '1.1'] or ['10.36.78.53;4;5'] -> ['10.36.78.53, '4', '5']
                if '/' in location:
                    port = location.split('/')
                    port_group_number = port[1].split('.')[0]

                if ';' in location:
                    port = location.split(';')
                    port_group_number = port[1]

                if int(port_group_number) not in Common_vars.port_group_range[duthost.hostname]:
                    Common_vars.port_group_range[duthost.hostname].append(int(port_group_number))
                    Common_vars.snappi_port_groups[duthost.hostname][int(port_group_number)] = {'rx_ports': [],
                                                                                                'tx_ports': [],
                                                                                                'queue_id_list': [],
                                                                                                'flows': []}
        Common_vars.get_queue_id_weight[duthost.hostname] = {}


def define_tx_rx_inter_port_testing(Common_vars, snappi_port_configs, rx_port_index):
    """
    For "INTER-PORT" testing

    - Create tx_ports|rx_ports list

    SCHEDULER|scheduler.1
    SCHEDULER|scheduler.8
    SCHEDULER|scheduler.0
    SCHEDULER|scheduler.6
    SCHEDULER|scheduler.7
    SCHEDULER|scheduler.4
    SCHEDULER|scheduler.9
    SCHEDULER|scheduler.5
    SCHEDULER|scheduler.2
    SCHEDULER|scheduler.3
    SCHEDULER|scheduler.10

    "SCHEDULER": {
        "scheduler.0": {
            "type": "DWRR",
            "weight": "95"
        },
        "scheduler.1": {
            "type": "DWRR",
            "weight": "5"
        },
        "scheduler.2": {
            "type": "DWRR",
            "weight": "1"
        },
        "scheduler.3": {
            "type": "DWRR",
            "weight": "10"
        },
        "scheduler.4": {
            "type": "DWRR",
            "weight": "20"
        },
        "scheduler.5": {
            "type": "DWRR",
            "weight": "30"
        },
        "scheduler.6": {
            "type": "DWRR",
            "weight": "15"
        },
        "scheduler.7": {
            "type": "DWRR",
            "weight": "25"
        },
        "scheduler.8": {
            "type": "DWRR",
            "weight": "40"
        },
        "scheduler.9": {
            "type": "DWRR",
            "weight": "50"
        },
        "scheduler.10": {
            "type": "DWRR",
            "weight": "60"
        }
    }

 "Ethernet0|0": {
            "scheduler": "scheduler.3",
            "wred_profile": "AZURE_LOSSLESS"
        },
        "Ethernet0|1": {
            "scheduler": "scheduler.3",
            "wred_profile": "AZURE_LOSSLESS"
        },
        "Ethernet0|2": {
            "scheduler": "scheduler.4",
            "wred_profile": "AZURE_LOSSLESS"
        },
        "Ethernet0|3": {
            "scheduler": "scheduler.5",
            "wred_profile": "AZURE_LOSSLESS"
        },
        "Ethernet0|4": {
            "scheduler": "scheduler.3",
            "wred_profile": "AZURE_LOSSLESS"
        },
        "Ethernet0|5": {
            "scheduler": "scheduler.3",
            "wred_profile": "AZURE_LOSSLESS"
        },
        "Ethernet0|6": {
            "scheduler": "scheduler.3",
            "wred_profile": "AZURE_LOSSLESS"
        },
        "Ethernet0|7": {
            "scheduler": "scheduler.3",
            "wred_profile": "AZURE_LOSSLESS"
        },
        "Ethernet0|8": {
            "scheduler": "scheduler.3",
            "wred_profile": "AZURE_LOSSLESS"
        },
        "Ethernet0|9": {
            "scheduler": "scheduler.3",
            "wred_profile": "AZURE_LOSSLESS"
        }

    """
    logger.info(f'Inter-port testing. rx-port index: {rx_port_index} ...')

    # 1> Get all of the dut hosts first
    all_dut_host_names = []
    for snappi_port in snappi_port_configs:
        if snappi_port['duthost'].hostname not in all_dut_host_names:
            all_dut_host_names.append(snappi_port['duthost'].hostname)

    # 2> For each dut host, get port-groups.ports
    # Get unique port-group list from snappi port locations
    for dut_hostname in all_dut_host_names:
        # Get all the user defined ports for the test.  Ports are not neccessarily in
        # the order of 1,2,3,4.  It could be 1,3,5,7
        port_group_range = []

        for snappi_port in snappi_port_configs:
            if snappi_port['duthost'].hostname == dut_hostname:
                location = snappi_port['location']
                # ['10.36.84.33', '1.1'] or ['10.36.78.53;4;5'] -> ['10.36.78.53, '4', '5']
                if '/' in location:
                    port = location.split('/')
                    port_group = port[1].split('.')[0]

                if ';' in location:
                    port = location.split(';')
                    port_group = port[1]

                if int(port_group) not in port_group_range:
                    port_group_range.append(int(port_group))

        Common_vars.snappi_port_groups[dut_hostname] = {}

        # Group ports into 8 ports per Resource-Group (1=RxPort 7=TxPort)
        # snappi_port_number = 2 in this example -> 10.36.84.33/2.8
        for snappi_port_group_number in port_group_range:
            Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number] = {'rx_ports': [],
                                                                                      'tx_ports': [],
                                                                                      'port_list': [],
                                                                                      'queue_id_list': [],
                                                                                      'traffic_items': []}
            index = 0

            # The rx-port goes on rotation in the snappi_port_configs list of ports
            for snappi_port in snappi_port_configs:
                if snappi_port['duthost'].hostname == dut_hostname:
                    # As of this writing, the testcase requires 8 AriesOne ports
                    # The port location begins with 1.#
                    # 'location': '10.36.84.33/2.8'
                    if '/' in snappi_port['location']:
                        location_port_group_number = int(snappi_port['location'].split('/')[-1].split('.')[0])

                    if ';' in snappi_port['location']:
                        location_port_group_number = int(snappi_port['location'].split(';')[1])

                    if location_port_group_number == snappi_port_group_number:
                        Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['port_list'].append(
                            snappi_port)
                        Common_vars.tx_port_names_for_verify_port_up += f',{snappi_port["peer_port"]}'

        # Below will only be processed if the current dut has ports defined in links.csv file
        # port_group_range: port_group_range: [1, 3, 5]
        for snappi_port_group_number in port_group_range:
            if snappi_port_group_number != port_group_range[-1]:
                current_port_group_index = port_group_range.index(snappi_port_group_number)

                # This is the rx-port on the next physical port
                inter_port_group_number = port_group_range[current_port_group_index + 1]
            else:
                # The last port-group sends to the first port-group
                inter_port_group_number = port_group_range[0]

            # Get the next port-group as rx-port
            # Probably have to keep track of ports in each port-group-range from snappi_port_configs
            # ['locations'] -> '10.36.84.33/2.8'
            rx_port = Common_vars.snappi_port_groups[dut_hostname][inter_port_group_number]['port_list'][rx_port_index]
            Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['rx_ports'].append(rx_port)

            # Build the tx-port list

            for index, tx_port in enumerate(Common_vars.snappi_port_groups[dut_hostname][
                snappi_port_group_number
            ]['port_list']):
                if index != rx_port_index:
                    Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['tx_ports'].append(tx_port)
                    tx_port.update({'total_weight': 0})

            # Clean up the dict
            if len(Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['tx_ports']) == 0:
                del Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]

        for snappi_port_group_number in port_group_range:
            # Remove the list. Save memory.
            if snappi_port_group_number in Common_vars.snappi_port_groups[dut_hostname].keys():
                Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['port_list'] = []


def define_tx_rx_intra_port_testing(Common_vars, snappi_port_configs, rx_port_index):
    """
    For "INTRA-PORT" testing
    Create tx_ports|rx_ports list
    """
    logger.info(f'Intra-port testing. rx-port index: {rx_port_index} ...')

    # 1> Get all of the dut hosts first
    all_dut_host_names = []
    for snappi_port in snappi_port_configs:
        if snappi_port['duthost'].hostname not in all_dut_host_names:
            all_dut_host_names.append(snappi_port['duthost'].hostname)

    # 2> For each dut host, get port-groups.ports
    # Get unique port-group list from snappi port locations
    for dut_hostname in all_dut_host_names:
        # Get all the user defined ports for the test.  Ports are not neccessarily in
        # the order of 1,2,3,4.  It could be 1,3,5,7
        port_group_range = []

        # Get unique port-group list from snappi port locations
        for snappi_port in snappi_port_configs:
            if snappi_port['duthost'].hostname == dut_hostname:
                location = snappi_port['location']
                # ['10.36.84.33', '1.1'] or ['10.36.78.53;4;5'] -> ['10.36.78.53, '4', '5']
                if '/' in location:
                    port = location.split('/')
                    port_group = port[1].split('.')[0]

                if ';' in location:
                    port = location.split(';')
                    port_group = port[1]

                if int(port_group) not in port_group_range:
                    port_group_range.append(int(port_group))

        Common_vars.snappi_port_groups[dut_hostname] = {}

        # Group ports into 8 ports (For an 800G port: 1=RxPort 7=TxPort)
        # snappi_port_number = 2 in this example -> 10.36.84.33/2.8
        for snappi_port_group_number in port_group_range:
            Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number] = {'rx_ports': [],
                                                                                      'tx_ports': [],
                                                                                      'queue_id_list': [],
                                                                                      'traffic_items': []}
            index = 0

            # The rx-port goes on rotation in the snappi_port_configs list of ports
            for snappi_port in snappi_port_configs:
                if snappi_port['duthost'].hostname == dut_hostname:
                    # As of this writing, the testcase requires 8 AriesOne ports
                    # The port location begins with 1.#
                    # 'location': '10.36.84.33/2.8'
                    if '/' in snappi_port['location']:
                        location_port_group_number = int(snappi_port['location'].split('/')[-1].split('.')[0])

                    if ';' in snappi_port['location']:
                        location_port_group_number = int(snappi_port['location'].split(';')[1])

                    if location_port_group_number == snappi_port_group_number:
                        if index == rx_port_index:
                            Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['rx_ports'].append(
                                snappi_port
                            )
                        else:
                            # Preset the total_weight with 0. This will get incremented when calculating
                            # the tx-port total weight
                            snappi_port.update({'total_weight': 0})
                            Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['tx_ports'].append(
                                snappi_port
                            )
                            Common_vars.tx_port_names_for_verify_port_up += f',{snappi_port["peer_port"]}'

                        index += 1

            # Clean up the dict
            if len(Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['tx_ports']) == 0:
                del Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]


def define_rx_tx_ports(Common_vars, snappi_port_configs, flow_configs):
    """
    Create a mini data-base for all tx-ports in Common_vars.snappi_port_groups.
    Each Tx-Port has its own configs: queue_id weight, scheduler_id, line-rate.
    set_snappi_qos_traffic() will use Common_vars.snappi_port_groups['tx_ports'] to build flows.
    """
    # 1> Get all of the dut hosts first
    all_dut_host_names = []
    for snappi_port in snappi_port_configs:
        if snappi_port['duthost'].hostname not in all_dut_host_names:
            all_dut_host_names.append(snappi_port['duthost'].hostname)

    dut_hostname = all_dut_host_names[0]
    total_ports = flow_configs['total_tx_ports'] + 1

    Common_vars.current_int_scheduler_id[dut_hostname] = {}

    # Gather up all flows with unique queue IDs to configure the DUT's Eth
    # inteface queue IDs with user defined scheduler/weight
    got_queue_id = []
    if flow_configs['weight_distribution_type'] in ['sequential', 'all_flows_as_endpoint_flows_on_each_port']:
        flows = flow_configs['tx_port_flows']

    if flow_configs['weight_distribution_type'] == 'map_port_index_with_flow_index':
        flows = []
        for flow_group in flow_configs['tx_port_flows']:
            for flow in flow_group:
                if flow['queue_id'] not in got_queue_id:
                    flows.append(flow)
                    got_queue_id.append(flow['queue_id'])

    # Group ports into 8 ports (1=RxPort 7=TxPort)
    # snappi_port_number = 2 in this example -> 10.36.84.33/2.8
    for snappi_port_group_number in Common_vars.port_group_range[dut_hostname]:
        tx_port_index = 0

        for snappi_port_index, snappi_port in enumerate(snappi_port_configs):
            if snappi_port_index >= total_ports:
                break

            # snappi_port
            # {'ipAddress': '192.168.1.6', 'ipGateway': '192.168.1.3', 'prefix': 24, 'subnet': '192.168.1.0/24',
            # 'peer_device': 'sonic-s6100-dut1', 'src_mac_address': 'aa:00:00:00:00:04',
            # 'router_mac_address': '9c:69:ed:6f:92:f1', 'speed': '100000', 'snappi_speed_type': 'speed_100_gbps',
            # 'peer_port': 'Ethernet4', 'location': '10.36.84.34/1.5',
            # 'duthost': <MultiAsicSonicHost sonic-s6100-dut1>, 'api_server_ip': '10.36.84.36',
            # 'asic_type': 'broadcom', 'asic_value': None, 'port_id': '5',
            # 'fec': True, 'autoneg': False, 'flows': [{'flow_name': 'DUT_Name:sonic-s6100-dut1 Ethernet4
            # QID:4 TC:4 DSCP:4 scheduler.5 WT:15 Line_Rate:25 Expected_Rx_Gbps_Rate%:15', 'dscp_phb_value': '4',
            # 'queue_id': 4, 'scheduler_id': 'scheduler.5', 'weight': 15, 'line_rate': 25, 'frame_size': 1500}]}

            if snappi_port['duthost'].hostname:
                # Example: speed_100_gbps
                # port_speed = int(snappi_port['snappi_speed_type'].split('_')[1])
                port_speed = get_port_speed(snappi_port['snappi_speed_type'])

                # The port location begins with 1.#
                # 'location': '10.36.84.33/2.8' | 10.36.78.53;4;5
                if '/' in snappi_port['location']:
                    location_port_group_number = int(snappi_port['location'].split('/')[-1].split('.')[0])

                if ';' in snappi_port['location']:
                    location_port_group_number = int(snappi_port['location'].split(';')[1])

                if location_port_group_number == snappi_port_group_number:
                    Common_vars.current_int_scheduler_id[dut_hostname][snappi_port['peer_port']] = {'properties': []}

                    # Don't always expect the first port in a dut to be the RX port.
                    if (
                        snappi_port_index == 0 and
                        len(Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['rx_ports']) == 0
                    ):
                        Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['rx_ports'].append(
                            snappi_port
                        )
                    else:
                        message = (f'---- Appending Tx-Port: snappi_port_index:{snappi_port_index} '
                                   f'{snappi_port["peer_port"]} ---')
                        logger.info(message)

                        snappi_port.update({'flows': []})
                        Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['tx_ports'].append(
                            snappi_port
                        )
                        Common_vars.tx_port_names_for_verify_port_up += f',{snappi_port["peer_port"]}'

                        # Used in set_snappi_qos_traffic()
                        # Keep track of the Ethernet interface's queue_id and scheduler_id used for
                        # the tx-port flow configuration
                        if flow_configs['weight_distribution_type'] == 'sequential':
                            """
                            Test case 2.7 phase 1:
                                Weight: Port1=20 LR=30, Port2=50  LR=40, Port3=30  LR=40

                                Port 2 will have dedicated 40G as it is below the configured weight
                                Remaining is 60G and the weights configured for Port 1 and Port 2 are
                                20 & 30 respectively
                                So to find out how much it will send:
                                   For port 1: 60 * 20/50 = 24
                                   For port 2: 60 * 30/50 = 36
                            """
                            # Map flow index to port index
                            tx_port_details = {}
                            tx_port_queue_id = flow_configs['tx_port_flows'][tx_port_index]['queue_id']
                            tx_port_weight = flow_configs['tx_port_flows'][tx_port_index]['weight']
                            tx_port_line_rate = flow_configs['tx_port_flows'][tx_port_index]['line_rate']
                            tx_port_frame_size = flow_configs['tx_port_flows'][tx_port_index]['frame_size']
                            tx_port_scheduler_id = Common_vars.scheduler_to_weight_dict[dut_hostname][tx_port_weight]
                            Common_vars.get_queue_id_weight[dut_hostname].update({tx_port_queue_id: tx_port_weight})
                            traffic_class = (Common_vars.dut_qos_configs[dut_hostname]
                                             ['get_traffic_class_from_qid'][int(tx_port_queue_id)])
                            phb_value = (Common_vars.dut_qos_configs[dut_hostname]["get_dscp_from_traffic_class"]
                                         [traffic_class])
                            expected_rx_rate = flow_configs['tx_port_flows'][tx_port_index]['expected_line_rate']

                            flow_name = (f'DUT_Name:{dut_hostname} {snappi_port["peer_port"]} Speed:{port_speed} '
                                         f'QID:{tx_port_queue_id} TC:{traffic_class} DSCP:{phb_value} '
                                         f'{tx_port_scheduler_id} WT:{tx_port_weight} Line_Rate:{tx_port_line_rate} '
                                         f'Expected_Rx_Gbps_Rate%:{expected_rx_rate}')

                            Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['flows'].append(
                                {'flow_name': flow_name}
                            )
                            logger.info(f'Flow: {flow_name}')

                            tx_port_details.update({'flow_name': flow_name,
                                                    'dscp_phb_value': phb_value,
                                                    'queue_id': tx_port_queue_id,
                                                    'scheduler_id': tx_port_scheduler_id,
                                                    'weight': tx_port_weight,
                                                    'line_rate': tx_port_line_rate,
                                                    'frame_size': tx_port_frame_size,
                                                    'port_speed': port_speed})

                            snappi_port['flows'].append(tx_port_details)
                            tx_port_index += 1

                            # Used in get_dut_wred_stats()
                            if hasattr(Common_vars, 'dut_queue_stat_counters'):
                                if tx_port_queue_id not in Common_vars.dut_queue_stat_counters:
                                    Common_vars.dut_queue_stat_counters.append(tx_port_queue_id)

                        if flow_configs['weight_distribution_type'] == 'all_flows_as_endpoint_flows_on_each_port':
                            # Configure all flows to every port
                            for flow_config in flow_configs['tx_port_flows']:
                                tx_port_details = {}
                                tx_port_queue_id = flow_config['queue_id']
                                tx_port_weight = flow_config['weight']
                                tx_port_line_rate = flow_config['line_rate']
                                tx_port_frame_size = flow_config['frame_size']
                                tx_port_scheduler_id = (Common_vars.scheduler_to_weight_dict[dut_hostname]
                                                        [tx_port_weight])
                                Common_vars.get_queue_id_weight[dut_hostname].update({tx_port_queue_id: tx_port_weight})
                                traffic_class = (Common_vars.dut_qos_configs[dut_hostname]['get_traffic_class_from_qid']
                                                 [int(tx_port_queue_id)])
                                phb_value = (Common_vars.dut_qos_configs[dut_hostname]["get_dscp_from_traffic_class"]
                                             [traffic_class])
                                expected_rx_rate = flow_configs['tx_port_flows'][tx_port_index]['expected_line_rate']

                                flow_name = (
                                    f'DUT_Name:{dut_hostname} {snappi_port["peer_port"]} Speed:{port_speed} '
                                    f'QID:{tx_port_queue_id} TC:{traffic_class} DSCP:{phb_value} '
                                    f'{tx_port_scheduler_id} WT:{tx_port_weight} Line_Rate:{tx_port_line_rate} '
                                    f'Expected_Rx_Gbps_Rate%:{expected_rx_rate}'
                                )

                                Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['flows'].append(
                                    {'flow_name': flow_name}
                                )
                                logger.info(f'Flow: {flow_name}')

                                tx_port_details.update({'flow_name': flow_name,
                                                        'dscp_phb_value': phb_value,
                                                        'queue_id': tx_port_queue_id,
                                                        'scheduler_id': tx_port_scheduler_id,
                                                        'weight': tx_port_weight,
                                                        'line_rate': tx_port_line_rate,
                                                        'frame_size': tx_port_frame_size,
                                                        'port_speed': port_speed})

                                snappi_port['flows'].append(tx_port_details)

                                # Used in get_dut_wred_stats()
                                if hasattr(Common_vars, 'dut_queue_stat_counters'):
                                    if tx_port_queue_id not in Common_vars.dut_queue_stat_counters:
                                        Common_vars.dut_queue_stat_counters.append(tx_port_queue_id)

                        if flow_configs['weight_distribution_type'] == 'map_port_index_with_flow_index':
                            """
                            Map tx_port_flows list index to port index.
                            And apply each flow from the list to the tx_port.

                            flow_configs = {'total_tx_ports': 2,
                            'weight_distribution_type': 'map_port_index_with_flow_index',
                            'tx_port_flows': [({'queue_id': 1, 'weight': 25, 'line_rate': 20, 'frame_size': 64},
                                               {'queue_id': 2, 'weight': 25, 'line_rate': 25, 'frame_size': 512},
                                               {'queue_id': 3, 'weight': 25, 'line_rate': 15, 'frame_size': 1024},
                                               {'queue_id': 4, 'weight': 25, 'line_rate': 20, 'frame_size': 1500}),
                                              ({'queue_id': 1, 'weight': 25, 'line_rate': 20, 'frame_size': 64},
                                               {'queue_id': 2, 'weight': 25, 'line_rate': 15, 'frame_size': 512},
                                               {'queue_id': 3, 'weight': 25, 'line_rate': 25, 'frame_size': 1024},
                                               {'queue_id': 4, 'weight': 25, 'line_rate': 20, 'frame_size': 1500})
                                            ]}
                            """
                            flow_configurations = flow_configs['tx_port_flows'][tx_port_index]

                            for flow_config in flow_configurations:
                                tx_port_details = {}
                                tx_port_queue_id = flow_config['queue_id']
                                tx_port_weight = flow_config['weight']
                                tx_port_line_rate = flow_config['line_rate']
                                tx_port_frame_size = flow_config['frame_size']
                                tx_port_scheduler_id = (Common_vars.scheduler_to_weight_dict[dut_hostname]
                                                        [tx_port_weight])

                                Common_vars.get_queue_id_weight[dut_hostname].update(
                                    {tx_port_queue_id: tx_port_weight})
                                traffic_class = (Common_vars.dut_qos_configs[dut_hostname]
                                                 ['get_traffic_class_from_qid'][int(tx_port_queue_id)])
                                phb_value = (Common_vars.dut_qos_configs[dut_hostname]["get_dscp_from_traffic_class"]
                                             [traffic_class])

                                # flow_name = f'DUT_Name:{dut_hostname} {snappi_port["peer_port"]} Speed:{port_speed}
                                # QID:{tx_port_queue_id} TC:{traffic_class} DSCP:{phb_value} {tx_port_scheduler_id}
                                # WT:{tx_port_weight} Line_Rate:{tx_port_line_rate}
                                # Expected_Rx_Gbps_Rate%:{expected_rx_rate}'
                                flow_name = (f'DUT_Name:{dut_hostname} {snappi_port["peer_port"]} Speed:{port_speed} '
                                             f'QID:{tx_port_queue_id} TC:{traffic_class} DSCP:{phb_value} '
                                             f'{tx_port_scheduler_id} WT:{tx_port_weight} '
                                             f'Line_Rate:{tx_port_line_rate}')

                                Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['flows'].append(
                                    {'flow_name': flow_name}
                                )
                                logger.info(f'Flow: {flow_name}')

                                tx_port_details.update({'flow_name': flow_name,
                                                        'dscp_phb_value': phb_value,
                                                        'queue_id': tx_port_queue_id,
                                                        'scheduler_id': tx_port_scheduler_id,
                                                        'weight': tx_port_weight,
                                                        'line_rate': tx_port_line_rate,
                                                        'frame_size': tx_port_frame_size,
                                                        'port_speed': port_speed})

                                snappi_port['flows'].append(tx_port_details)

                                # Used in get_dut_wred_stats()
                                if hasattr(Common_vars, 'dut_queue_stat_counters'):
                                    if tx_port_queue_id not in Common_vars.dut_queue_stat_counters:
                                        Common_vars.dut_queue_stat_counters.append(tx_port_queue_id)

                            tx_port_index += 1

                    # Configure DUT scheduler/weight:
                    # For each DUT Ethernet interface, configure all common queue_id with user defined scheduler/weight
                    #     ---- Appending Tx-Port: snappi_port_index:1 Ethernet1 ---
                    #     Configuring DUT: Ethernet1|1 with scheduler.5
                    #     Configuring DUT: Ethernet1|2 with scheduler.8
                    #     Configuring DUT: Ethernet1|3 with scheduler.6
                    #     Configuring DUT: Ethernet1|4 with scheduler.6
                    for flow in flows:
                        interface_queue_id = flow['queue_id']
                        weight = flow['weight']

                        # Set the weight the test case requires
                        scheduler_id = Common_vars.scheduler_to_weight_dict[dut_hostname][weight]

                        current_scheduler_id = get_int_scheduler(duthost=snappi_port['duthost'],
                                                                 interface=snappi_port['peer_port'],
                                                                 queue_id=interface_queue_id)

                        Common_vars.current_int_scheduler_id[dut_hostname][snappi_port['peer_port']]['properties'] \
                            .append({'queue_id': interface_queue_id,
                                     'scheduler_id': current_scheduler_id['scheduler']})

                        # Configure all DUT RX-Port and TX-Port interfaces to have common scheduler ID \
                        # across all the Queue IDs
                        config_int_queue_id_scheduler_id(Common_vars,
                                                         snappi_port['duthost'],
                                                         interface=snappi_port['peer_port'],
                                                         queue_id=interface_queue_id,
                                                         scheduler_id=scheduler_id)

        # Clean up the dict
        if len(Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['tx_ports']) == 0:
            del Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]


def get_port_speed(snappi_port_speed):
    port_speed = {'speed_100_gbps': '100Gbps',
                  'speed_200_gbps': '200Gbps',
                  'speed_400_gbps': '400Gbps',
                  'speed_800_gbps': '800Gbps',
                  }
    return port_speed[snappi_port_speed]


def map_scheduler_id_by_weight(duthost):
    """
    Dynamically read dut config_db for scheduler ID mapping to weight values
    Because every dut could have scheduler ID with different value
    And each test case requires using a different weight

    There is no CLI command to verify the scheduler
    sonic-db-cli CONFIG_DB keys "SCHEDULER|*"
    sonic-db-cli CONFIG_DB hgetall "SCHEDULER|scheduler.0"

    SCHEDULER|scheduler.1 - > {"type": "DWRR", "weight": "1"}
    SCHEDULER|scheduler.3
    SCHEDULER|scheduler.2

    RETURN
       {1:  'scheduler.0',
        10: 'scheduler.1',
        40: 'scheduler.6',
        50: 'scheduler.7',
        25: 'scheduler.5',
        30: 'scheduler.3',
        20: 'scheduler.2',
        15: 'scheduler.4'}
    """
    weight_to_scheduler_dict = {}
    scheduler_to_weight_dict = {}
    scheduler_to_weight_dict[duthost.hostname] = {}
    weight_to_scheduler_dict[duthost.hostname] = {}

    # Get SCHEDULER data
    """
    SCHEDULER|scheduler.0
    SCHEDULER|scheduler.1
    SCHEDULER|scheduler.2
    SCHEDULER|scheduler.3
    SCHEDULER|scheduler.4
    SCHEDULER|scheduler.5
    SCHEDULER|scheduler.6
    SCHEDULER|scheduler.7
    SCHEDULER|scheduler.8
    SCHEDULER|scheduler.9
    SCHEDULER|scheduler.10
    """
    verify_dut_scheduler_str = duthost.shell('sonic-db-cli CONFIG_DB keys "SCHEDULER|*"')['stdout']

    for configured_scheduler in verify_dut_scheduler_str.split('\n'):
        # Get each scheduler_id type and weight -> {'type': 'DWRR', 'weight': '1'}
        logger.info(f'Reading DUT {duthost.hostname}: sonic-db-cli CONFIG_DB hgetall "{configured_scheduler}"')
        scheduler_data = duthost.shell(
            f'sonic-db-cli CONFIG_DB hgetall "{configured_scheduler}"')['stdout'].replace("'", '"')

        scheduler_data_dict_data = json.loads(scheduler_data)
        # {"type": "DWRR", "weight": "1"}
        scheduler_id = configured_scheduler.replace('SCHEDULER|', '')
        scheduler_to_weight_dict[duthost.hostname][int(scheduler_data_dict_data['weight'])] = scheduler_id
        weight_to_scheduler_dict[duthost.hostname][scheduler_id] = int(scheduler_data_dict_data['weight'])

    # scheduler_to_weight_dict:  Get the scheduler_id from the weight
    # weight_to_scheduler_dict:  Get the weight from the scheduler_id
    return scheduler_to_weight_dict, weight_to_scheduler_dict


def config_int_queue_id_scheduler_id(Common_vars, duthost, interface, queue_id, scheduler_id):
    """
    interface: Etherenet0
    queue_id: <str> number
    scheduler_id: <str> scheduler.2
    """
    logger.info(f'Configuring DUT: {interface}|{queue_id} with {scheduler_id}')
    duthost.shell(f'sudo sonic-db-cli CONFIG_DB hset "QUEUE|{interface}|{queue_id}" scheduler "{scheduler_id}"')


def get_int_scheduler(duthost, interface, queue_id):
    # sonic-db-cli CONFIG_DB hgetall "QUEUE|Ethernet1|2"
    output = duthost.shell(f'sonic-db-cli CONFIG_DB hgetall "QUEUE|{interface}|{queue_id}"')['stdout']
    # Return: {'scheduler': 'scheduler.1', 'wred_profile': 'AZURE_LOSSLESS'}
    scheduler_id_obj = json.loads(output.replace("'", '"'))
    return scheduler_id_obj


def verify_int_queue_id_scheduler(duthost, interface, queue_id, expected_scheduler_id, weight):
    output_obj = get_int_scheduler(duthost, interface, queue_id)

    if output_obj['scheduler'] == expected_scheduler_id:
        logger.info(f'Verified {interface}|{queue_id} expected {expected_scheduler_id} for weight={weight}')
    else:
        pytest_assert(False, f'Verified interface failed: {interface}|{queue_id} \
            expected {expected_scheduler_id} Got: {output_obj["scheduler"]} for weight={weight}')


def save_dut_config(duthost, config_file='/etc/sonic/config_db.json'):
    logger.info(f'Save DUT configurations to: {config_file}')
    duthost.shell(f'sudo config save {config_file} -y')


def read_dut_configs(Common_vars, duthosts):
    """
    For test_qos_dwrr.py only
    Read all dut config_db configurations one-by-one to build a data structure for creating snappi traffic items
    """
    for dut in duthosts:
        # If traffic chassis's are chained, don't expect ports from multiple chassis's.
        # Could be using ports from just one chassis.
        if dut.hostname not in Common_vars.snappi_port_groups.keys():
            return

        verify_dut_scheduler_obj = read_dut_qos_configurations_dwrr(Common_vars, dut)
        set_snappi_qos_traffic_dwrr(Common_vars, dut, verify_dut_scheduler_obj)


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
    """
    dut_hostname = duthost.hostname
    logger.info(f'Read_dut_qos_configurations: {dut_hostname} ...')

    # 'sonic-s6100-dut1': {
    #     'scheduler': {'scheduler.2': 1, 'scheduler.9': 50, 'scheduler.8': 40, 'scheduler.1': 5,
    # 'scheduler.7': 25, 'scheduler.6': 15,
    #                   'scheduler.5': 30, 'scheduler.0': 95, 'scheduler.3': 10, 'scheduler.4': 20,
    # 'scheduler.10': 60},
    #     'weight_list': [1, 50, 40, 5, 25, 15, 30, 95, 10, 20, 60],
    #     'get_traffic_class_from_qid': {0: '0', 1: '1', 2: '2', 3: '3', 4: '4', 5: '5', 6: '6', 7: '7',
    # 8: '8', 9: '9'},
    #     'get_dscp_from_traffic_class': {'1': '9', '5': '46', '3': '3', '4': '4', '6': '48', '2': '5',
    # '0': '8'}
    # }
    Common_vars.dut_qos_configs[dut_hostname] = {'scheduler': {},
                                                 'weight_list': [],
                                                 'get_traffic_class_from_qid': {},
                                                 'get_dscp_from_traffic_class': {}
                                                 }

    verify_dut_scheduler_str = duthost.shell("show runningconfiguration all")['stdout']
    verify_dut_scheduler_obj = json.loads(verify_dut_scheduler_str)

    # Check for required QoS KEYS in the dut's configuration  'PFC_WD',
    for config_db_key in ['BUFFER_POOL', 'BUFFER_PG',  'SCHEDULER', 'TC_TO_QUEUE_MAP',
                          'DSCP_TO_TC_MAP', 'TC_TO_PRIORITY_GROUP_MAP', 'QUEUE', 'WRED_PROFILE']:
        pytest_assert(config_db_key in verify_dut_scheduler_obj.keys(), f'{config_db_key} is required in config_db')

    # TC_TO_QUEUE_MAP: Left_side is traffic_class. Right side is queue_id.
    for traffic_class, queue_id in verify_dut_scheduler_obj['TC_TO_QUEUE_MAP']['AZURE'].items():
        Common_vars.dut_qos_configs[dut_hostname]['get_traffic_class_from_qid'][int(queue_id)] = traffic_class

    # With Traffic Class, get the DSCP
    for dscp_value, traffic_class in verify_dut_scheduler_obj['DSCP_TO_TC_MAP']['AZURE'].items():
        Common_vars.dut_qos_configs[dut_hostname]["get_dscp_from_traffic_class"][traffic_class] = dscp_value

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
                # Note: For some reason, reading the dut inserts {i} to QUEUE interfaces -> Ethernet99|{i}
                if interface.split('|')[1] == '{i}':
                    continue

                eth_interface = interface.split('|')[0]

                if snappi_peer_port_name == eth_interface:
                    eth_interface_queue_id = int(interface.split('|')[1])
                    if snappi_rx_port['peer_port'] == eth_interface:
                        if int(eth_interface_queue_id) not in properties['queue_id_list']:
                            properties['queue_id_list'].append(eth_interface_queue_id)

    for schedulerId, weight in Common_vars.weight_to_scheduler_dict[dut_hostname].items():
        Common_vars.dut_qos_configs[dut_hostname]['scheduler'].update({schedulerId: weight})

        # Go through each port in "QUEUE" to get all its queue to add the scheduler's weight
        Common_vars.dut_qos_configs[dut_hostname]['weight_list'].append(int(weight))

    return verify_dut_scheduler_obj


def read_dut_qos_configurations_dwrr(Common_vars, duthost):
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

    'queue_id_list': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    """
    dut_hostname = duthost.hostname

    Common_vars.dut_qos_configs[dut_hostname] = {'scheduler': {},
                                                 'weight_list': [],
                                                 'get_traffic_class_from_qid': {},
                                                 'get_dscp_from_traffic_class': {}
                                                 }

    verify_dut_scheduler_str = duthost.shell("show runningconfiguration all")['stdout']
    verify_dut_scheduler_obj = json.loads(verify_dut_scheduler_str)

    # Check for required QoS KEYS in the dut's configuration  'PFC_WD',
    for config_db_key in ['BUFFER_POOL', 'BUFFER_PG',  'SCHEDULER', 'TC_TO_QUEUE_MAP',
                          'DSCP_TO_TC_MAP', 'TC_TO_PRIORITY_GROUP_MAP', 'QUEUE', 'WRED_PROFILE']:
        pytest_assert(config_db_key in verify_dut_scheduler_obj.keys(), f'{config_db_key} is required in config_db')

    # TC_TO_QUEUE_MAP: Left_side is traffic_class. Right side is queue_id.
    for traffic_class, queue_id in verify_dut_scheduler_obj['TC_TO_QUEUE_MAP']['AZURE'].items():
        Common_vars.dut_qos_configs[dut_hostname]['get_traffic_class_from_qid'][int(queue_id)] = traffic_class

    # With Traffic Class, get the DSCP
    for dscp_value, traffic_class in verify_dut_scheduler_obj['DSCP_TO_TC_MAP']['AZURE'].items():
        Common_vars.dut_qos_configs[dut_hostname]["get_dscp_from_traffic_class"][traffic_class] = dscp_value

    # Read just the rx-port to get a list of queue IDs
    for port_group_num, properties in Common_vars.snappi_port_groups[dut_hostname].items():
        for snappi_rx_port in properties['rx_ports']:
            snappi_peer_port_name = snappi_rx_port['peer_port']

            for interface in verify_dut_scheduler_obj['QUEUE'].keys():
                # Note: For some reason, reading the dut inserts {i} to QUEUE interfaces -> Ethernet99|{i}
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

                # total_tx_ports should be 7 for an 800G physical port (1 for rx-port, 7 for tx-port)
                if (
                    snappi_peer_port_name == eth_interface and
                    tx_port_queue_id_counter < Common_vars.total_tx_ports_per_physical_port
                ):
                    eth_interface_queue_id = int(interface.split('|')[1])
                    eth_interface_scheduler_id = verify_dut_scheduler_obj['QUEUE'][interface]['scheduler']
                    scheduler_id_weight = verify_dut_scheduler_obj['SCHEDULER'][eth_interface_scheduler_id]['weight']
                    snappi_tx_port['total_weight'] += int(scheduler_id_weight)
                    tx_port_queue_id_counter += 1

    for schedulerId, weight in Common_vars.weight_to_scheduler_dict[dut_hostname].items():
        Common_vars.dut_qos_configs[dut_hostname]['scheduler'].update({schedulerId: weight})

        # Go through each port in "QUEUE" to get all its queue to add the scheduler's weight
        Common_vars.dut_qos_configs[dut_hostname]['weight_list'].append(int(weight))

    return verify_dut_scheduler_obj


def reload_dut(duthost, config_db_filename):
    """
    admin@str-7060x6-64pe-stress-01:/etc/sonic$ sudo config reload dwrr_wred_bgp.json -f
    Acquired lock on /etc/sonic/reload.lock
    Clear current config and reload config in config_db from the file(s) dwrr_wred_bgp.json ? [y/N]:
    """
    logger.info(f'Reloading DUT with: {config_db_filename}')
    duthost.shell(f'sudo config reload {config_db_filename} -f -y')


def verify_dut_ports_up(duthost: object, tx_port_names: str):
    """
    Interface    Lanes    Speed    MTU    FEC        Alias    Vlan    Oper    Admin   Type    Asym PFC
    -----------  -------  -------  -----  -----  -----------  ------  ------  -------  ----  ----------
    Ethernet0   17  100G   9100  rs  Ethernet1/1   trunk   up  up  OSFP 8X Pluggable Transceiver off
    Ethernet1   18  100G   9100  rs  Ethernet1/2   trunk   up  up  OSFP 8X Pluggable Transceiver off
    Ethernet2   19  100G   9100  rs  Ethernet1/3   trunk   up  up  OSFP 8X Pluggable Transceiver off
    Ethernet3   20  100G   9100  rs  Ethernet1/4   trunk   up  up  OSFP 8X Pluggable Transceiver off
    """
    start_counter = 1
    end_counter = 60
    interface_name_list = tx_port_names.split(',')
    total_interfaces = len(interface_name_list)

    while True:
        # all_ports_are_up = True
        output = duthost.shell(f'show int status {tx_port_names}')['stdout']

        for index, line in enumerate(output.split('\n')):
            if index == 0:
                # Ethernet0  17  100G   9100  rs  Ethernet1/1 trunk  up  up  OSFP 8X Pluggable Transceiver off
                line_items = [item.strip() for item in line.split('  ') if item != '']

                operIndex = line_items.index('Oper')
                adminIndex = line_items.index('Admin')
                interfaceIndex = line_items.index('Interface')
                continue

            if index == 1:
                continue

            line_item_list = [item for item in line.split(' ') if item != '']
            interface = line_item_list[interfaceIndex]
            operStatus = line_item_list[operIndex]
            adminStatus = line_item_list[adminIndex]
            logger.info(f'Verifying DUT ports up: {interface}  Oper_Status:{operStatus}  Admin_Status:{adminStatus}')

            if start_counter < end_counter and total_interfaces != 0:
                if interface in interface_name_list:
                    if operStatus == 'up' and adminStatus == 'up':
                        total_interfaces -= 1

            if start_counter < end_counter and total_interfaces == 0:
                logger.info('verify_dut_ports_up: All testing interfaces are up')
                return

            if start_counter == end_counter and total_interfaces != 0:
                pytest_assert(False, f'It has been {(end_counter * 10)} seconds and port are not up')

        if start_counter <= end_counter and total_interfaces != 0:
            logger.info(f'{start_counter}/{end_counter} tries.  Wait 10 seconds ...')
            start_counter += 1
            time.sleep(10)


def set_snappi_qos_traffic_dwrr(Common_vars, duthost, verify_dut_scheduler_obj):
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
            'pfc_queue_id_generator': {
                'scheduler.0': <generator object round_robin at 0x7f6d7ec397b0>,
                'scheduler.1': <generator object round_robin at 0x7f6d7ec39740>,
                'scheduler.2': <generator object round_robin at 0x7f6d7ec396d0>
            }
        }
    }
    """
    flow_number = 0
    for port_group_num, properties in Common_vars.snappi_port_groups[dut_hostname].items():
        # Each tx-port uses a unique queue ID
        # queue_id_list: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        queue_id_generator = round_robin(properties['queue_id_list'])
        rx_port_topology_group_index = properties['rx_ports'][0]['topology_group_index']

        # Each Tx-Port sends with a unique queue ID of the Rx Port
        # tx_port: {'ipAddress': '192.168.1.2', 'ipGateway': '192.168.1.3', 'prefix': 24,
        #           'subnet': '192.168.1.0/24', 'src_mac_address': 'aa:00:00:00:00:01',
        #           'router_mac_address': '9c:69:ed:6f:92:f1', 'speed': '100000',
        #           'snappi_speed_type': 'speed_100_gbps', 'peer_port': 'Ethernet1',
        #           'location': '10.36.84.34/1.2',
        #           'duthost': <MultiAsicSonicHost sonic-s6100-dut1>, 'api_server_ip': '10.36.84.36',
        #           'asic_type': 'broadcom', 'asic_value': None, 'port_id': '2', 'fec': True,
        #           'autoneg': False, 'total_weight': 0}
        for tx_port in properties['tx_ports']:
            tx_port_location = tx_port['location']
            dut_port_name = tx_port['peer_port']
            ip_address = tx_port['ipAddress']
            src_mac_address = tx_port['src_mac_address']
            router_mac_address = tx_port['router_mac_address']
            topology_group_index = tx_port['topology_group_index']

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

            # {0: '0', 1: '1', 2: '2', 3: '3', 4: '4', 5: '5', 6: '6', 7: '7', 8: '8', 9: '9'}
            traffic_class = Common_vars.dut_qos_configs[dut_hostname]['get_traffic_class_from_qid'][int(queue_id)]
            # {'0': '0', '1': '1', '10': '10', '9': '9', '2': '2', '3': '3', '4': '4', '5': '5', '6': '6',
            # '7': '7', '8': '8'}
            phb_value = Common_vars.dut_qos_configs[dut_hostname]["get_dscp_from_traffic_class"][traffic_class]
            # if phb_value in [3, 4]:
            #      pbh_value = [phb_value]

            ethernet_port_name_with_queue_id = f'{dut_port_name}|{queue_id}'
            # "Ethernet0|0": {
            #    "scheduler": "scheduler.0"

            port_queue_scheduler_id = verify_dut_scheduler_obj['QUEUE'][ethernet_port_name_with_queue_id]['scheduler']
            # Get the scheduler.# weight
            # {'scheduler.3': 30, 'scheduler.8': 50, 'scheduler.0': 1, 'scheduler.7': 40, 'scheduler.10': 95,
            # 'scheduler.2': 20, 'scheduler.5': 15, 'scheduler.1': 10, 'scheduler.9': 60, 'scheduler.4': 5,
            # 'scheduler.6': 25}
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
            # NOTE: Use only one space in between words because verifying stats does a split(' ')[6]
            traffic_item_name = (
                f'{dut_hostname}:{dut_port_name} SrcTopology:{topology_group_index} '
                f'DestTopology:{rx_port_topology_group_index} QID:{queue_id} TC:{traffic_class} DSCP:{phb_value} '
                f'{port_queue_scheduler_id} WT:{weight} TTl_WT:{total_weight} Expected_Rx_Line_Rate:{weight}'
            )
            logger.info(f'Flow {flow_number}: {traffic_item_name}')
            flow_number += 1

            properties['traffic_items'].append({'traffic_item_name': traffic_item_name,
                                                'pfc_queue_id': queue_id,
                                                'dscp_phb_value': phb_value,
                                                'ip_address': ip_address,
                                                'router_mac_address': router_mac_address,
                                                'src_mac_address': src_mac_address,
                                                'location': tx_port_location,
                                                'dut_hostname': dut_hostname,
                                                'peer_port': dut_port_name,
                                                'topology_group_index': topology_group_index,
                                                'rx_port_topology_group_index': rx_port_topology_group_index,
                                                })

            if hasattr(Common_vars, 'dut_queue_stat_counters'):
                if queue_id not in Common_vars.dut_queue_stat_counters:
                    Common_vars.dut_queue_stat_counters.append(queue_id)


def set_snappi_qos_traffic(Common_vars, duthost, verify_dut_scheduler_obj):
    """
    Used by test_qos_dwrr.py test case only

    This function reads one duthost configs.
    Create a dut_qos_configs dict of each dut_host containing its qos/pfc configs
    Create traffic flow list

    typeOfTest: Options: dwrr | dwrr+wred

    'tx_ports': [
        {
            'ipAddress': '192.168.1.2',
            'ipGateway': '192.168.1.3',
            'prefix': 24,
            'subnet': '192.168.1.0/24',
            'src_mac_address': 'aa:00:00:00:00:01',
            'router_mac_address': '9c:69:ed:6f:92:f1',
            'speed': '100000',
            'snappi_speed_type': 'speed_100_gbps',
            'peer_port': 'Ethernet1',
            'location': '10.36.84.34/1.2',
            'duthost': <MultiAsicSonicHost sonic-s6100-dut1>,
            'api_server_ip': '10.36.84.36',
            'asic_type': 'broadcom',
            'asic_value': None,
            'port_id': '2',
            'fec': True,
            'autoneg': False,
            'flows': [
                {'queue_id': 1, 'scheduler_id': 'scheduler.7', 'weight': 25, 'line_rate': 20},
                {'queue_id': 2, 'scheduler_id': 'scheduler.7', 'weight': 25, 'line_rate': 25},
                {'queue_id': 3, 'scheduler_id': 'scheduler.7', 'weight': 25, 'line_rate': 15},
                {'queue_id': 4, 'scheduler_id': 'scheduler.7', 'weight': 25, 'line_rate': 20}
            ]
        }

    traffic_item: DUT_Name:sonic-s6100-dut1 Ethernet1 QID:1 TC:1 DSCP:1 scheduler.5 WT:30
    Line_Rate:35 Expected_Rx_Gbps_Rate%:30
    traffic_item: DUT_Name:sonic-s6100-dut1 Ethernet2 QID:2 TC:2 DSCP:2 scheduler.8 WT:40
    Line_Rate:45 Expected_Rx_Gbps_Rate%:40
    traffic_item: DUT_Name:sonic-s6100-dut1 Ethernet3 QID:3 TC:3 DSCP:3 scheduler.6 WT:15
    Line_Rate:25 Expected_Rx_Gbps_Rate%:15
    traffic_item: DUT_Name:sonic-s6100-dut1 Ethernet4 QID:4 TC:4 DSCP:4 scheduler.6 WT:15
    Line_Rate:25 Expected_Rx_Gbps_Rate%:15
    """
    dut_hostname = duthost.hostname

    # Configure in groups of 8 ports. 7 tx-ports and 1 rx-port. Rotate the list of ports to be the rx_port so
    # every port is tested as a rx-port.  Create traffic items for each dut.

    for port_group_num, properties in Common_vars.snappi_port_groups[dut_hostname].items():
        rx_port_topology_group_index = properties['rx_ports'][0]['topology_group_index']

        # Each Tx-Port sends with a unique queue ID of the Rx Port
        for index, tx_port in enumerate(properties['tx_ports']):
            tx_port_location = tx_port['location']
            dut_port_name = tx_port['peer_port']
            ip_address = tx_port['ipAddress']
            src_mac_address = tx_port['src_mac_address']
            router_mac_address = tx_port['router_mac_address']
            # port_speed = tx_port['port_speed']
            topology_group_index = tx_port['topology_group_index']

            for flow_configs in tx_port['flows']:
                # Every port round robins a queue ID
                queue_id = flow_configs['queue_id']
                line_rate = flow_configs['line_rate']
                traffic_class = Common_vars.dut_qos_configs[dut_hostname]['get_traffic_class_from_qid'][int(queue_id)]
                phb_value = Common_vars.dut_qos_configs[dut_hostname]["get_dscp_from_traffic_class"][traffic_class]

                # {'scheduler': 'scheduler.7'}
                port_queue_scheduler_id = flow_configs['scheduler_id']

                # Get the scheduler.# weight
                weight = int(Common_vars.weight_to_scheduler_dict[dut_hostname][port_queue_scheduler_id])

                """
                    "QUEUE": {
                        "Ethernet0|0": {
                            "scheduler": "scheduler.0"
                        },
                        "Ethernet0|1": {
                            "scheduler": "scheduler.0"
                        }
                """

                if Common_vars.type_of_test == 'dwrr+wred':
                    expected_rx_rate = int(weight)

                # NOTE: Use only one space in between words because verifying stats does a split(' ')[6]
                traffic_item_name = (f'DUT_Name:{dut_hostname} {dut_port_name} SrcTopology:{topology_group_index} '
                                     f'DestTopology:{rx_port_topology_group_index} QID:{queue_id} '
                                     f'TC:{traffic_class} DSCP:{phb_value} '
                                     f'{port_queue_scheduler_id} WT:{weight} Line_Rate:{line_rate} '
                                     f'Expected_Rx_Gbps_Rate%:{expected_rx_rate}')
                logger.info(f'traffic_item: {traffic_item_name}')

                properties['traffic_items'].append({'traffic_item_name': traffic_item_name,
                                                    'queue_id': queue_id,
                                                    'dscp_phb_value': phb_value,
                                                    'ip_address': ip_address,
                                                    'router_mac_address': router_mac_address,
                                                    'src_mac_address': src_mac_address,
                                                    'location': tx_port_location,
                                                    'dut_hostname': dut_hostname,
                                                    'peer_port': dut_port_name,
                                                    'scheduler_id': port_queue_scheduler_id,
                                                    'line_rate': line_rate,
                                                    'frame_size': flow_configs.get('frame_size',
                                                                                   Common_vars.frame_size)
                                                    })

                # Used in get_dut_wred_stats()
                if hasattr(Common_vars, 'dut_queue_stat_counters'):
                    if queue_id not in Common_vars.dut_queue_stat_counters:
                        Common_vars.dut_queue_stat_counters.append(queue_id)


def round_robin(value_list):
    """
    For DWRR script only
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
        If weight = 15 and total weight = 40 (5, 15, 20) <-- If there were only 3 txPorts.
        Get their scheduler.id weights

        5/40 = 0.125 x 100 = 12.5 (allocated to queue)
        100 - 12.5 = 87.5% loss
    """
    pct_allocated_to_queue = (weight / total_weight) * 100
    expected_loss_pct = 100 - pct_allocated_to_queue

    # weight:15 total_weight:43  pct_allocated:34.883720930232556  expected_loss:65.11627906976744 float:65.1
    return round(float(expected_loss_pct), 1)


def create_snappi_flows_dwrr(Common_vars, duthosts, snappi_api, snappi_port_configs):
    """
    Creating a many-to-one traffic pattern
    """
    # Configure Traffic Items
    # Currently, Snappi cannot reconfigure/recreate/remove traffic items.  Using Respy until Snappi issue is resolved.
    '''
    for port_group_num, properties in Common_vars.snappi_port_groups[dut_hostname].items():
        for tx_port in properties['traffic_items']:
            # tx_port: {'traffic_item_name': 'sonic-s6100-dut1:Ethernet16|0 scheduler.0 Weight:5 phb:8 87.5% loss',
            # 'pfc_queue_id': 0, 'dscp_phb_value': 8, 'ip_address': '192.168.1.4',
            # 'src_mac_address': 'aa:00:00:00:00:01',
            # 'location': '10.36.84.33/2', 'dut_hostname': 'sonic-s6100-dut1'}
            dut_hostname = tx_port['dut_hostname']
            rx_port_details = properties['rx_ports'][0]

            flow = Common_vars.snappi_configs.flows.flow(name=tx_port['traffic_item_name'])[-1]
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
    for dut_host in duthosts:
        if dut_host.hostname not in Common_vars.snappi_port_groups.keys():
            continue

        for port_group_index, (port_group_num, properties) in enumerate(
            Common_vars.snappi_port_groups[dut_host.hostname].items()
        ):
            rx_port_topology = snappi_api._ixnetwork.Topology.find()[properties['rx_ports'][0]['topology_group_index']]

            """
             'rx_ports': [
                        {
                            'ipAddress': '192.168.1.2',
                            'ipGateway': '192.168.1.3',
                            'prefix': 24,
                            'subnet': '192.168.1.0/24',
                            'src_mac_address': 'aa:00:00:00:00:00',
                            'router_mac_address': '9c:69:ed:6f:92:51',
                            'speed': '100000',
                            'snappi_speed_type': 'speed_100_gbps',
                            'peer_port': 'Ethernet0',
                            'location': '10.36.84.33/1.1',
                            'duthost': <MultiAsicSonicHost sonic-s6100-dut1>,
                            'api_server_ip': '10.36.84.33',
                            'asic_type': 'broadcom',
                            'asic_value': None,
                            'topology_group_index': 0
                        }
                    ],
            """
            for index, tx_port in enumerate(properties['traffic_items']):
                # tx_port:  {'traffic_item_name': 'sonic-s6100-dut1:Ethernet22 SrcIp:10.10.15.2 QID:5 TC:5 DSCP:5
                # scheduler.3 WT:10 TTl_WT:100 Expected_Rx_Line_Rate:10',
                # 'pfc_queue_id': 5, 'dscp_phb_value': '5', 'ip_address': '10.10.15.2',
                # 'router_mac_address':'9c:69:ed:6f:92:f1', 'src_mac_address': '10:17:00:00:00:1f',
                # 'location': '10.36.84.34/3.7', 'dut_hostname': 'sonic-s6100-dut1',
                # 'peer_port': 'Ethernet22','topology_group_index': 14}
                tx_port_topology = snappi_api._ixnetwork.Topology.find()[tx_port['topology_group_index']]
                flowObj = snappi_api._ixnetwork.Traffic.TrafficItem.add(
                    Name=tx_port['traffic_item_name'],
                    TrafficType=Common_vars.subnet_type.lower(),
                    BiDirectional=False)

                flowObj.EndpointSet.add(Sources=tx_port_topology, Destinations=rx_port_topology)
                flowObj.Tracking.find()[0].TrackBy = ['trackingenabled0']
                configElement = flowObj.ConfigElement.find()[0]
                configElement.FrameRate.update(Type='percentLineRate', Rate=Common_vars.line_rate_percentage)

                flow_delay_sec = 0
                configElement.TransmissionControl.update(Type='continuous',
                                                         Duration=Common_vars.flow_duration_seconds,
                                                         StartDelay=int(sec_to_nanosec(flow_delay_sec)))

                configElement.FrameSize.FixedSize = Common_vars.frame_size
                ethernetStackObj = snappi_api._ixnetwork.Traffic.TrafficItem.find(
                    Name=tx_port['traffic_item_name']).ConfigElement.find()[0].Stack.find(StackTypeId='ethernet$')

                ethernetStackObj = configElement.Stack.find(StackTypeId='ethernet$')
                pfcQueueObj = ethernetStackObj.Field.find(DisplayName='PFC Queue')
                pfcQueueObj.ValueType = 'singleValue'
                pfcQueueObj.SingleValue = tx_port['pfc_queue_id']

                ipv4PrecedenceField = configElement.Stack.find(
                    DisplayName=Common_vars.subnet_type).Field.find(DisplayName='Class selector PHB')

                # DSCP configurations and references
                ipv4PrecedenceField.ActiveFieldChoice = True
                ipv4PrecedenceField.ValueType = 'singleValue'
                ipv4PrecedenceField.SingleValue = tx_port['dscp_phb_value']

                # For WRED testing.  Set Unused field bit to 2 for marking ECN packets.
                ipv4PrecedenceField.find('Unused').find(
                    FieldTypeId="ipv4.header.priority.ds.phb.classSelectorPHB.unused"
                ).ActiveFieldChoice = True

                ipv4PrecedenceField.find('Unused').find(
                    FieldTypeId="ipv4.header.priority.ds.phb.classSelectorPHB.unused"
                ).ValueType = 'singleValue'

                ipv4PrecedenceField.find('Unused').find(
                    FieldTypeId="ipv4.header.priority.ds.phb.classSelectorPHB.unused"
                ).SingleValue = 2

                message = (f'Creating Flow: Port-Group-{port_group_num} {tx_port_topology.Name} -> '
                           f'{rx_port_topology.Name} DSCP:{tx_port["dscp_phb_value"]} QID:{tx_port["pfc_queue_id"]}')
                logger.info(message)


def create_snappi_flows(Common_vars, duthosts, config, snappi_api, snappi_port_configs,
                        traffic_duration=10, enable_pkt_sequence_checking=False):
    """
    Creating a many-to-one traffic pattern
    """
    # Configure Traffic Items
    # Currently, Snappi cannot reconfigure/recreate/remove traffic items.  Using Respy until Snappi issue is resolved.
    '''
    for port_group_num, properties in Common_vars.snappi_port_groups[dut_hostname].items():
        for tx_port in properties['traffic_items']:
            # tx_port: {'traffic_item_name': 'sonic-s6100-dut1:Ethernet16|0 scheduler.0 Weight:5 phb:8 87.5% loss',
            # 'queue_id': 0, 'dscp_phb_value': 8, 'ip_address': '192.168.1.4', 'src_mac_address': 'aa:00:00:00:00:01',
            # 'location': '10.36.84.33/2', 'dut_hostname': 'sonic-s6100-dut1'}
            dut_hostname = tx_port['dut_hostname']

            flow = config.flows.flow(name=tx_port['traffic_item_name'])[-1]
            flow.tx_rx.port.tx_name = tx_port['location']
            flow.tx_rx.port.rx_name = rx_port_details['location']
            eth, ipv4 = flow.packet.ethernet().ipv4()
            eth.src.value = tx_port['src_mac_address']
            eth.dst.value = rx_port_details['src_mac_address']

            if pfcQueueGroupSize == 8:
                eth.pfc_queue.value = tx_port['queue_id']
            else:
                eth.pfc_queue.value = pfcQueueValueDict[tx_port['queue_id']]

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

    if enable_pkt_sequence_checking:
        logger.info('Enabling flow statistics sequence checking...')
        snappi_api._ixnetwork.Traffic.Statistics.SequenceChecking.Enabled = True

        logger.info('Confiuring flow large error thresholdL 6500...')
        snappi_api._ixnetwork.Traffic.LargeErrorThreshhold = 6500

    set_rx_port_flag = False

    for dut_host in duthosts:
        if dut_host.hostname not in Common_vars.snappi_port_groups.keys():
            continue

        for port_group_num, properties in Common_vars.snappi_port_groups[dut_host.hostname].items():
            if set_rx_port_flag is False and len(properties['rx_ports']) > 0:
                # rx_port_details = properties['rx_ports'][0]
                set_rx_port_flag = True

            if len(properties['tx_ports']) == 0:
                continue

            for tx_port_index, tx_port in enumerate(properties['tx_ports']):
                # {'ipAddress': '192.168.1.4', 'ipGateway': '192.168.1.3', 'prefix': 24,
                # 'subnet': '192.168.1.0/24', 'src_mac_address': 'aa:00:00:00:00:02',
                # 'router_mac_address': '9c:69:ed:6f:92:f1', 'speed': '100000',
                # 'snappi_speed_type': 'speed_100_gbps',
                # 'peer_port': 'Ethernet2', 'location': '10.36.84.34/1.3',
                # 'duthost': <MultiAsicSonicHost sonic-s6100-dut1>, 'api_server_ip': '10.36.84.36',
                # 'asic_type': 'broadcom', 'asic_value': None, 'port_id': '3',
                # 'fec': True, 'autoneg': False,
                # 'flows': [{'flow_name': 'DUT_Name:sonic-s6100-dut1 Ethernet2 QID:1 TC:1
                #             DSCP:1 scheduler.5 WT:30 Line_Rate:70 Expected_Rx_Gbps_Rate%:30',
                #            'dscp_phb_value': '1', 'queue_id': 1,
                # 'scheduler_id': 'scheduler.5', 'weight': 30, 'line_rate': 70, 'frame_size': 1500},
                # {'flow_name': 'DUT_Name:sonic-s6100-dut1 Ethernet2 QID:2 TC:2 DSCP:2 scheduler.8 WT:40
                # Line_Rate:70 Expected_Rx_Gbps_Rate%:40', 'dscp_phb_value': '2', 'queue_id': 2,
                # 'scheduler_id': 'scheduler.8', 'weight': 40, 'line_rate': 70, 'frame_size': 1500},
                # {'flow_name': 'DUT_Name:sonic-s6100-dut1 Ethernet2 QID:3 TC:3 DSCP:3 scheduler.6
                #  WT:15 Line_Rate:70 Expected_Rx_Gbps_Rate%:15', 'dscp_phb_value': '3', 'queue_id': 3,
                # 'scheduler_id': 'scheduler.6',
                # 'weight': 15, 'line_rate': 70, 'frame_size': 1500},
                # {'flow_name': 'DUT_Name:sonic-s6100-dut1 Ethernet2 QID:4 TC:4 DSCP:4 scheduler.6
                # WT:15 Line_Rate:70 Expected_Rx_GPS_Rate%:15', 'dscp_phb_value': '4', 'queue_id': 4,
                # 'scheduler_id': 'scheduler.6', 'weight': 15, 'line_rate': 70, 'frame_size': 1500}]}

                if Common_vars.flows_per_port == 'multiple':
                    # Creating multiple endpoint flows per traffic item
                    # Have to create the traffic item outside the endpoint-flow for-loop
                    traffic_item_name = f'SrcPort: {tx_port["peer_port"]}'
                    flowObj = snappi_api._ixnetwork.Traffic.TrafficItem.add(
                        Name=traffic_item_name,
                        TrafficType=Common_vars.subnet_type.lower(),
                        BiDirectional=False
                    )
                    flowObj.RoundRobinPacketOrdering = True

                # Flow == traffic item
                for flow_index, flow in enumerate(tx_port['flows']):
                    """
                     {'flow_name': 'DUT_Name:sonic-s6100-dut1 Ethernet2 QID:4 TC:4 DSCP:4 scheduler.6
                     WT:15 Line_Rate:70 Expected_Rx_Gbps_Rate%:15',
                      'dscp_phb_value': '4', 'queue_id': 4, 'scheduler_id': 'scheduler.6', 'weight': 15,
                      'line_rate': 70, 'frame_size': 1500}
                     [
                        {'flow_name': 'DUT_Name:sonic-s6100-dut1 Ethernet1 QID:1 TC:1 DSCP:1 scheduler.7
                         WT:25 Line_Rate:20 Expected_Rx_Gbps_Rate%:25', 'dscp_phb_value': '1',
                         'queue_id': 1, 'scheduler_id': 'scheduler.7', 'weight': 25, 'line_rate': 20,
                         'frame_size': 64},
                        {'flow_name': 'DUT_Name:sonic-s6100-dut1 Ethernet1 QID:2 TC:2 DSCP:2 scheduler.7
                         WT:25 Line_Rate:25 Expected_Rx_Gbps_Rate%:25', 'dscp_phb_value': '2',
                         'queue_id': 2, 'scheduler_id': 'scheduler.7', 'weight': 25, 'line_rate': 25,
                         'frame_size': 512},
                        {'flow_name': 'DUT_Name:sonic-s6100-dut1 Ethernet1 QID:3 TC:3 DSCP:3 scheduler.7
                         WT:25 Line_Rate:15 Expected_Rx_Gbps_Rate%:25', 'dscp_phb_value': '3',
                         'queue_id': 3, 'scheduler_id': 'scheduler.7', 'weight': 25, 'line_rate': 15,
                         'frame_size': 1024},
                        {'flow_name': 'DUT_Name:sonic-s6100-dut1 Ethernet1 QID:4 TC:4 DSCP:4 scheduler.7
                         WT:25 Line_Rate:20 Expected_Rx_Gbps_Rate%:25', 'dscp_phb_value': '4',
                         'queue_id': 4, 'scheduler_id': 'scheduler.7', 'weight': 25, 'line_rate': 20,
                         'frame_size': 1500}
                    ]
                    """

                    if Common_vars.flows_per_port == 'single':
                        # Each flow is a traffic item/src-port.  Just one traffic-item/one endpoint per src-port.
                        logger.info(f'Creating flow: {flow["flow_name"]}')
                        flowObj = snappi_api._ixnetwork.Traffic.TrafficItem.add(
                            Name=flow['flow_name'],
                            TrafficType=Common_vars.subnet_type.lower(),
                            BiDirectional=False
                        )

                    # For raw traffic: flowObj.EndpointSet.add(
                        # Sources=tx_port_vport.Protocols.find(), Destinations=rx_port_vport.Protocols.find())
                    # Create a Config Element (flow)
                    flowObj.EndpointSet.add(Sources=snappi_api._ixnetwork.Topology.find()[tx_port_index + 1],
                                            Destinations=snappi_api._ixnetwork.Topology.find()[0])

                    if Common_vars.flows_per_port == 'single':
                        # If single, this means each flow is a traffic item. So config_element is always 0.
                        config_element_index = 0
                        configElement = flowObj.ConfigElement.find()[config_element_index]
                        flowObj.Tracking.find()[0].TrackBy = ['trackingenabled0']

                    elif Common_vars.flows_per_port == 'multiple':
                        # Creating multiple endpoint-set per traffic item
                        config_element_index = flow_index
                        flowObj.Tracking.find()[0].TrackBy = ['trackingenabled0', 'flowGroup0']
                        configElement = flowObj.HighLevelStream.find()[config_element_index]
                        configElement.Name = flow['flow_name']
                        logger.info(f'Flow name: {configElement.Name}')

                    flow_delay_sec = 0
                    configElement.TransmissionControl.update(Type='continuous', Duration=traffic_duration,
                                                             StartDelay=int(sec_to_nanosec(flow_delay_sec)))
                    configElement.FrameRate.update(Type='percentLineRate', Rate=flow['line_rate'])

                    if type(flow['frame_size']) is list:
                        # Custom list of frame sizes
                        configElement.FrameSize.Type = 'weightedPairs'
                        configElement.FrameSize.WeightedPairs = flow['frame_size']
                    else:
                        # Single frame size
                        configElement.FrameSize.FixedSize = flow['frame_size']

                    ethernetStackObj = configElement.Stack.find(StackTypeId='ethernet$')
                    pfcQueueObj = ethernetStackObj.Field.find(DisplayName='PFC Queue')
                    pfcQueueObj.ValueType = 'singleValue'
                    pfcQueueObj.SingleValue = flow['queue_id']

                    ipv4PrecedenceField = configElement.Stack.find(
                        DisplayName=Common_vars.subnet_type).Field.find(DisplayName='Default PHB')

                    ipv4PrecedenceField.ActiveFieldChoice = True
                    ipv4PrecedenceField.ValueType = 'singleValue'
                    ipv4PrecedenceField.SingleValue = flow['dscp_phb_value']

                    # if int(flow['dscp_phb_value']) == 8:
                    #     ipv4PrecedenceField.find('Unused').find(
                    #     FieldTypeId="ipv4.header.priority.ds.phb.classSelectorPHB.unused").ActiveFieldChoice = True
                    #     ipv4PrecedenceField.find('Unused').find(
                    #     FieldTypeId="ipv4.header.priority.ds.phb.classSelectorPHB.unused").ValueType = 'singleValue'
                    #     ipv4PrecedenceField.find('Unused').find(
                    #     FieldTypeId="ipv4.header.priority.ds.phb.classSelectorPHB.unused").SingleValue = 2
                    ipv4PrecedenceField.find('Unused').find(
                        FieldTypeId="ipv4.header.priority.ds.phb.defaultPHB.unused").ActiveFieldChoice = True
                    ipv4PrecedenceField.find('Unused').find(
                        FieldTypeId="ipv4.header.priority.ds.phb.defaultPHB.unused").ValueType = 'singleValue'
                    ipv4PrecedenceField.find('Unused').find(
                        FieldTypeId="ipv4.header.priority.ds.phb.defaultPHB.unused").SingleValue = 2

    return config


def config_snappi_egress_tracking_wred(Common_vars, duthosts, snappi_api, egress_encapsulation,
                                       egress_custom_offset_bits,
                                       egress_width_bits, egress_offset="Custom",
                                       egress_stat_view_name='EgressStats'):
    """
    Configure Snappi egress tracking to verify dut egress packets
    Note: Currently, snappi has no support to do this.
    """
    # Apply traffic or else configuring egress tracking won't work.
    snappi_api._ixnetwork.Traffic.Apply()

    for traffic_item_obj in snappi_api._ixnetwork.Traffic.TrafficItem.find():
        tracking = traffic_item_obj.Tracking.find()[0]
        tracking.Egress.Encapsulation = egress_encapsulation
        tracking.Egress.CustomOffsetBits = egress_custom_offset_bits
        tracking.Egress.CustomWidthBits = egress_width_bits
        tracking.Egress.Offset = egress_offset
        traffic_item_obj.EgressEnabled = True
        traffic_item_obj.Generate()

    snappi_api._ixnetwork.Traffic.Apply()

    egressTrackingOffsetFilter = f'Custom: ({egress_width_bits} bits at offset {egress_custom_offset_bits})'

    # Create Egress Stats
    logger.info('\n\nCreating new statview for egress stats...')
    snappi_api._ixnetwork.Statistics.View.add(Caption=egress_stat_view_name,
                                              TreeViewNodeName='Egress Custom Views',
                                              Type='layer23TrafficFlow',
                                              Visible=True)

    Common_vars.egress_statview_obj = snappi_api._ixnetwork.Statistics.View.find(Caption=egress_stat_view_name)

    # Dynamically get the Traffic Items Filter ID
    availableTrafficItemFilterId = []

    for eachTrafficItemFilterId in Common_vars.egress_statview_obj.AvailableTrafficItemFilter.find():
        availableTrafficItemFilterId.append(eachTrafficItemFilterId.href)

    if availableTrafficItemFilterId == []:
        pytest_assert(False, 'config_snappi_egress_tracking_wred: No traffic item filter ID found')

    logger.info(f'\n\navailableTrafficItemFilterId: {availableTrafficItemFilterId}\n')

    # # /api/v1/sessions/1/ixnetwork/statistics/view/12
    layer23TrafficFlowFilter = Common_vars.egress_statview_obj.Layer23TrafficFlowFilter.find()[0]
    layer23TrafficFlowFilter.EgressLatencyBinDisplayOption = 'showEgressRows'
    layer23TrafficFlowFilter.TrafficItemFilterIds = availableTrafficItemFilterId

    # Get the egress tracking filter
    egressTrackingFilter = None
    ingressTrackingFilter = None
    ingressTrackingFilterName = None

    # Show all the avaialable filter names/options
    for eachTrackingFilter in Common_vars.egress_statview_obj.AvailableTrackingFilter.find():
        # eachTrackingFilter.Name = Custom: (2 bits at offset 126)
        logger.info(f'\n\nAvailable tracking filters: {eachTrackingFilter.Name}\n')

        if bool(match('.*[0-9]+ bits at offset *[0-9]+|Flow Group', eachTrackingFilter.Name)):
            egressTrackingFilter = eachTrackingFilter.href

        if egressTrackingFilter is None:
            pytest_assert(False,
                          (f'config_snappi_egress_tracking_wred: Failed to locate your defined custom '
                           f'offsets: {egressTrackingOffsetFilter}'))

        if ingressTrackingFilterName is not None:
            if eachTrackingFilter.Name == ingressTrackingFilterName:
                ingressTrackingFilter = eachTrackingFilter.href

        # # /api/v1/sessions/1/ixnetwork/statistics/view/23/availableTrackingFilter/3
        logger.info(f'Located egressTrackingFilter: {egressTrackingFilter}')
        # egressTrackingFilter: /api/v1/sessions/1/ixnetwork/statistics/view/12/availableTrackingFilter/1
        layer23TrafficFlowFilter.EnumerationFilter.add(SortDirection='ascending',
                                                       TrackingFilterId=egressTrackingFilter)

        # This will include ingress tracking in the egress statview.
        if ingressTrackingFilterName is not None:
            layer23TrafficFlowFilter.EnumerationFilter.add(SortDirection='ascending',
                                                           TrackingFilterId=ingressTrackingFilter)

    for eachEgressStatCounter in Common_vars.egress_statview_obj.Statistic.find():
        eachEgressStatCounter.Enabled = True

    Common_vars.egress_statview_obj.Enabled = True
    Common_vars.egress_statview_obj.AutoUpdate = True

    # Problem: Configuring egress tracking resets the flow names to default name.
    #          Have to rename the flows with meaningful names.
    rename_flow_names(Common_vars, duthosts, snappi_api)


def rename_flow_names(Common_vars, duthosts, snappi_api):
    """
    Problem: After egress tracking configurations, the flow names are resetted.
    Solution: Create a function to rename the flow names
    """
    if Common_vars.flows_per_port == 'multiple':
        for dut_host in duthosts:
            if dut_host.hostname not in Common_vars.snappi_port_groups.keys():
                continue

            for port_group_num, properties in Common_vars.snappi_port_groups[dut_host.hostname].items():
                for flow_index, tx_port in enumerate(properties['tx_ports']):
                    flowObj = snappi_api._ixnetwork.Traffic.TrafficItem.find()[flow_index]
                    for flow_index, flow in enumerate(tx_port['flows']):
                        flow_name_obj = flowObj.HighLevelStream.find()[flow_index]
                        flow_name_obj.Name = flow['flow_name']

        # Must apply traffic after naming each flow or else the name will not be set
        snappi_api._ixnetwork.Traffic.Apply()


def clear_dut_stat_counters(duthosts):
    for dut_host in duthosts:
        logger.info(f'Clearing DUT stat counters: {dut_host.hostname}')

        logger.info('Entering: counterpoll wredqueue enable')
        dut_host.shell("counterpoll wredqueue enable")

        # for queue_id in Common_vars.dut_queue_stat_counters:
        #     logger.info(f'sudo ecnconfig -q {queue_id} on')
        #     dut_host.shell(f"sudo ecnconfig -q {queue_id} on")

        logger.info('Entering: sonic-clear queue wredcounters')
        dut_host.shell("sonic-clear queue wredcounters")


def run_traffic(Common_vars, duthosts, snappi_api, config):
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
    control_state = snappi_api.control_state()
    control_state.choice = control_state.TRAFFIC
    control_state.traffic.choice = control_state.traffic.FLOW_TRANSMIT

    # Test case 6 issue: Flow group names get reset when executing Regenerate
    # Must rename the flow groups
    rename_flow_names(Common_vars, duthosts, snappi_api)

    control_state.traffic.flow_transmit.state = control_state.traffic.flow_transmit.START
    res = snappi_api.set_control_state(control_state)
    if len(res.warnings) > 0:
        # ['IxNet - PFC queue ID is adjusted from the configured value: 4 to the maximum supported value: 3',
        #  'IxNet - PFC queue ID is adjusted from the configured value: 5 to the maximum supported value: 3',
        #  'IxNet - PFC queue ID is adjusted from the configured value: 6 to the maximum supported value: 3']
        logger.warn(res.warnings)

    return control_state


def stop_traffic(snappi_api, control_state):
    """
    Run traffic and dump per-flow statistics

    Args:
        control_state: The control_state object provided by run_traffic

    Returns:
        per-flow statistics (list)
    """
    logger.info('Stopping traffic ...')
    control_state.traffic.flow_transmit.state = control_state.traffic.flow_transmit.STOP
    snappi_api.set_control_state(control_state)
    time.sleep(5)


def get_statistics(snappi_api, stat_view_name, stat_view_columns, show_tabulated_table=False):
    """
    Note: Snappi could only retrieve Traffic Items. So, we have to use restpy to get other stats

    snappi_api:           IxNetwork RestPy session object
    stat_view_name:       IxNetwork stat view name: "Traffic Items", "Flow Statistics", "Port Statistics"
    stat_view_columns:    The stat view column names to get
    show_tabulated_table: Display flows in tabulated table
    """
    flow_stats = snappi_api._assistant.StatViewAssistant(stat_view_name)
    if len(flow_stats.Rows.RawData) == 0:
        pytest_assert(False, 'get_statistics: No flow stats available')

    flow_stat_column_headers = flow_stats.ColumnHeaders

    if flow_stat_column_headers[0] == 'Gap':
        flow_stat_column_headers.pop(0)

    data_frame = pd.DataFrame(flow_stats.Rows.RawData, columns=flow_stat_column_headers)
    data_frame_selected = data_frame[stat_view_columns]

    if show_tabulated_table:
        # logger.info(f"\n{tabulate(data_frame_selected, headers='keys', tablefmt='pretty', numalign='right',
        # stralign='left', colalign=('left', 'left', 'left'))}")

        table = tabulate(data_frame_selected,
                         headers='keys',
                         tablefmt='pretty',
                         numalign='right',
                         stralign='left',
                         colalign=('left', 'left', 'left'))

        logger.info(f"\n{table}")

    return data_frame_selected.to_dict(orient="records")


def delete_flows(Common_vars, snappi_api, remove_egress_stat_view=False):
    logger.info('Removing flow configurations ...')
    for traffic_item in snappi_api._ixnetwork.Traffic.TrafficItem.find():
        traffic_item.remove()

    if remove_egress_stat_view:
        Common_vars.egress_statview_obj.remove()


def delete_flows_2(Common_vars, duthosts, snappi_api):
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


def is_at_least_one_gigabit(value: int) -> bool:
    """
    Check if input value is at least one gigabit
    """
    GIGABIT = 10**9  # 1 gigabit = 1,000,000,000 bits
    return value >= GIGABIT


def convert_number_to_gigabits(value):
    if len(str(value)) == 1:
        return int(str(value).ljust(10, '0'))

    if len(str(value)) == 2:
        return int(str(value).ljust(11, '0'))

    if len(str(value)) == 3:
        return int(str(value).ljust(12, '0'))


def get_dut_wred_stats(Common_vars, duthosts):
    """
    Go to every dut and get wred stats

    DUT: show queue wredcounters Ethernet0
         Port    TxQ    WredDrp/pkts    WredDrp/bytes    EcnMarked/pkts    EcnMarked/bytes
    ---------  -----  --------------  ---------------  ----------------  -----------------
    Ethernet0    UC0             N/A              N/A                 0                  0
    Ethernet0    UC1             N/A              N/A         1,032,731      1,549,096,500
    Ethernet0    UC2             N/A              N/A        32,098,257     48,147,385,500
    Ethernet0    UC3             N/A              N/A         3,454,820      5,182,230,000
    Ethernet0    UC4             N/A              N/A        32,110,021     48,165,031,500
    """
    doOnce = True

    for dut_host in duthosts:
        Common_vars.tgen_flow_stats[dut_host.hostname] = {}

        for port_group_num, properties in Common_vars.snappi_port_groups[dut_host.hostname].items():
            rx_port_details = properties['rx_ports'][0]

            # Get the index position of TxQ first
            if doOnce:
                doOnce = False

                logger.info(f'DUT: show queue wredcounters {rx_port_details["peer_port"]}')
                dut_stat_counters_obj = dut_host.shell(f"show queue wredcounters \
                    {rx_port_details['peer_port']}")['stdout']

                # Get DUT first title line for TxQ and EcnMarked/pkts index positionsss for stats
                for line in dut_stat_counters_obj.split('\n'):
                    regexMatch = search('(.*TxQ.*)', line)
                    if regexMatch:
                        column_names_line = regexMatch.group(0)
                        column_names_line = column_names_line.split(' ')
                        column_names_line2 = [item for item in column_names_line if item != '']
                        txq_index = column_names_line2.index('TxQ')
                        egress_pkt_index = column_names_line2.index('EcnMarked/pkts')
                        logger.info(line)
                        break

            for line in dut_stat_counters_obj.split('\n'):
                logger.info(line)

                if rx_port_details['peer_port'] in line:
                    each_line = line.split(' ')
                    # Remove invisible characters in each line
                    each_line2 = [item for item in each_line if item != '']
                    # each_line2: ['Ethernet64', 'UC0', '43,894,549', '179,792,072,704']
                    tx_queue_stat = each_line2[txq_index]
                    if 'UC' not in tx_queue_stat:
                        break

                    tx_queue = tx_queue_stat.split('UC')[1]

                    for queue in Common_vars.dut_queue_stat_counters:
                        if int(tx_queue) == queue:
                            Common_vars.tgen_flow_stats[dut_host.hostname][queue] = {}
                            egress_pkts = int(each_line2[egress_pkt_index].replace(',', ''))
                            Common_vars.tgen_flow_stats[dut_host.hostname].update(
                                {queue: {'egressPackets': egress_pkts}})


def backup_config_db(Common_vars, dut_host):
    """
    The DWRR test cases modifies the config, saves the config to config_db.json and reload.
    Backup the original config_db.json file and restore it at the end of the test.
    """
    if hasattr(Common_vars, "backup_config_db") and Common_vars.backup_config_db is False:
        logger.info(f'Backing up {Common_vars.config_db_file} to {Common_vars.backup_config_db_file} ...')
        dut_host.shell(f"sudo cp {Common_vars.config_db_file} {Common_vars.backup_config_db_file}")


def restore_config_db(Common_vars):
    if hasattr(Common_vars, "backup_config_db") and Common_vars.backup_config_db:
        logger.info('Restoring original config_db.json from backup ...')
        Common_vars.dut_hosts[0].shell(f"sudo cp {Common_vars.backup_config_db_file} {Common_vars.config_db_file}")
        Common_vars.dut_hosts[0].shell(f"sudo chmod 777 {Common_vars.config_db_file}")
        Common_vars.dut_hosts[0].shell(f"sudo rm {Common_vars.backup_config_db_file}")
        reload_dut(Common_vars.dut_hosts, Common_vars.config_db_file)
        verify_dut_ports_up(Common_vars.dut_hosts[0], Common_vars.tx_port_names_for_verify_port_up)


def verify_dwrr_pass_criteria(Common_vars, snappi_api, control_state_obj):
    selected_view_columns = ['Tx Port', 'Rx Port', 'Traffic Item', 'Tx L1 Rate (bps)', 'Rx L1 Rate (bps)']

    for iteration in range(1, 4):
        verify_again = False
        failed_messages = []

        flow_stats = get_statistics(snappi_api,
                                    stat_view_name='Flow Statistics',
                                    stat_view_columns=selected_view_columns,
                                    show_tabulated_table=True)

        for flow in flow_stats:
            # flow:{'Tx Port': 'Port_2', 'Rx Port': 'Port_1', 'Traffic Item': 'sonic-s6100-dut1:Ethernet1
            # SrcIp:192.168.1.2 QID:0 TC:0 DSCP:0 scheduler.1 WT:10 TTl_WT:100 Expected_Loss%:90.0',
            #       'Tx L1 Rate (bps)': '99999998112.000', 'Rx L1 Rate (bps)': '10000019568.000'}
            tx_port = flow['Tx Port']
            rx_port = flow['Rx Port']
            tx_l1_rate = int(float(flow['Tx L1 Rate (bps)']))
            tx_l1_rate_whole_number = round(tx_l1_rate / 1000000000)

            rx_l1_rate = int(float(flow['Rx L1 Rate (bps)']))
            rx_l1_rate_whole_number = round(rx_l1_rate / 1000000000)

            if tx_l1_rate_whole_number == 0 or rx_l1_rate_whole_number == 0:
                logger.info('Stats not ready.  Trying again ...')
                verify_again = True
                break

            traffic_item = flow['Traffic Item']

            regex_weight = search('.* WT:([0-9]+) +', traffic_item)
            flow_weight = int(regex_weight.group(1))

            regex_queue_id = search('.* QID:([0-9]+) +', traffic_item)
            queue_id = int(regex_queue_id.group(1))

            regex_dscp = search('.* DSCP:([0-9]+) +', traffic_item)
            dscp = int(regex_dscp.group(1))

            regex_scheduler = search('.* scheduler.([0-9]+) +', traffic_item)
            scheduler = int(regex_scheduler.group(1))

            # percentage_whole_number = int("%.0f" % (Common_vars.pass_threshold_pct * 100))
            port_speed = 100
            # 100 x .02 = 2
            acceptable_threshold = port_speed * Common_vars.pass_threshold_pct
            # If weight=40, 40-2=38 (low)
            traffic_flow_pass_criteria_low = round(flow_weight - acceptable_threshold)
            traffic_flow_pass_criteria_high = round(flow_weight + acceptable_threshold)

            # This gives the Gbps value: 10.000019568
            rx_gbps_rate_whole_number = round(rx_l1_rate / 1000000000)

            message = (f'verify_dwrr_pass_criteria: {tx_port} -> {rx_port}  Queue_ID:{queue_id}  DSCP:{dscp}'
                       f'Scheduler:{scheduler} Weight:{flow_weight}  Tx-L1-Rate:{tx_l1_rate_whole_number}/Gbps '
                       f'Rx-L1-Rate:{rx_gbps_rate_whole_number}/Gbps  '
                       f'Expected:{traffic_flow_pass_criteria_low}-{traffic_flow_pass_criteria_high}/Gbps')
            logger.info(message)

            if (
                rx_gbps_rate_whole_number < traffic_flow_pass_criteria_low
                or rx_gbps_rate_whole_number > traffic_flow_pass_criteria_high
            ):
                verify_again = True
                failure = (f'FAILED: {tx_port} -> {rx_port}  Queue_ID:{queue_id}  DSCP:{dscp} Scheduler:{scheduler} '
                           f'Weight:{flow_weight}  '
                           f'Expected:{traffic_flow_pass_criteria_low}-{traffic_flow_pass_criteria_high}/Gbps  '
                           f'Rx:{rx_gbps_rate_whole_number}/Gbps')
                failed_messages.append(failure)
                logger.info(failure)
                time.sleep(3)

        if verify_again is False:
            break

    if verify_again:
        logger.info('verify_dwrr_pass_criteria: calling stop_traffic ...')
        stop_traffic(snappi_api, control_state_obj)
        delete_flows(Common_vars, snappi_api, remove_egress_stat_view=False)
        pytest_assert(False, failed_messages)


def verify_line_rate(Common_vars, duthosts, snappi_api,  control_state_obj):
    """
    Verify line rate stats that includes egress tracking stats.
    This means traffic must have egress tracking configured.
    Line rate is verified at the flow level's Rx L1 Rate (Gbps)
    """
    selected_view_columns = ['Tx Port', 'Rx Port', 'Traffic Item', 'Tx L1 Rate (Gbps)',
                             'Egress Tracking', 'Rx L1 Rate (Gbps)']

    try:
        # Use range(1,4) to verify stats up to 3 times for stat correctness.
        # Sometimes the stat's snapshot line rate is a bit too low. Check stats again for up to 3x.
        for iteration in range(1, 4):
            verify_again = False

            flow_stats = get_statistics(snappi_api,
                                        stat_view_name=Common_vars.egress_stat_view_name,
                                        stat_view_columns=selected_view_columns,
                                        show_tabulated_table=True)

            for flow in flow_stats:
                # {'Tx Port': 'Port_2', 'Rx Port': 'Port_1', 'Traffic Item': 'sonic-s6100-dut1:Ethernet1
                # Speed:100Gbps QID:1 TC:1 DSCP:1 scheduler.7 WT:25 TTl_WT:100 Line_Rate:50 Expected_Rx_Gbps_Rate%:25',
                # 'Tx L1 Rate (Gbps)': '50.000', 'Egress Tracking': 'Custom: (2 bits at offset 126)',
                # 'Rx L1 Rate (Gbps)': '25.000'}
                egress_stats = flow['Egress Tracking']

                if egress_stats == '':
                    pytest_assert(False, 'No egress stats received')

                if flow['Traffic Item'] != '':
                    tx_port = flow['Tx Port']
                    rx_port = flow['Rx Port']
                    # tx_l1_rate = int(round(float(flow['Tx L1 Rate (Gbps)'])))
                    rx_l1_rate = int(round(float(flow['Rx L1 Rate (Gbps)'])))
                    traffic_item = flow['Traffic Item']
                    current_traffic_item = traffic_item
                    expected_rx_line_rate = int(traffic_item.split(' ')[-1].split(':')[1])
                    regex_weight = search('.* WT:([0-9]+) +', current_traffic_item)
                    flow_weight = int(regex_weight.group(1))
                    regex_port_speed = search('.* Speed:([0-9]+)', current_traffic_item)
                    port_speed = int(regex_port_speed.group(1))

                    percentage_whole_number = int("%.0f" % (Common_vars.pass_threshold_pct * 100))
                    # 100 x .02 = 2
                    acceptable_threshold = port_speed * Common_vars.pass_threshold_pct

                    # If weight=40, 40-2=38 (low).  40+2=42 (high)
                    traffic_flow_pass_criteria_low = round(expected_rx_line_rate - acceptable_threshold)
                    traffic_flow_pass_criteria_high = round(expected_rx_line_rate + acceptable_threshold)

                    result = ((round(rx_l1_rate) >= traffic_flow_pass_criteria_low) and
                              (round(rx_l1_rate) <= traffic_flow_pass_criteria_high))

                    """
                    stat_message = f'Verifying weight line rate stats: {tx_port} -> {rx_port} Weight:{flow_weight}  \
                        Tx-Rate:{flow["Tx L1 Rate (Gbps)"]}Gbps  Rx_Rate:{flow["Rx L1 Rate (Gbps)"]}Gbps  \
                            acceptable-range:{traffic_flow_pass_criteria_low}-{traffic_flow_pass_criteria_high} \
                                Exceptable-loss-Threshold:{percentage_whole_number}%  acceptable_threshold: \
                                    {acceptable_threshold} Result={result} {iteration}/3x'
                    """
                    stat_message = (
                        f'Verifying weight line rate stats: {tx_port} -> {rx_port} Weight:{flow_weight} '
                        f'Tx-Rate:{flow["Tx L1 Rate (Gbps)"]}Gbps  Rx_Rate:{flow["Rx L1 Rate (Gbps)"]}Gbps '
                        f'acceptable-range:{traffic_flow_pass_criteria_low}-{traffic_flow_pass_criteria_high} '
                        f'Exceptable-loss-Threshold:{percentage_whole_number}%  '
                        f'acceptable_threshold: {acceptable_threshold} Result={result} {iteration}/3x'
                    )

                    logger.info(stat_message)

                    if result is False and iteration == 3:
                        logger.info('verify_line_rate: calling stop_traffic ...')
                        stop_traffic(snappi_api, control_state_obj)
                        delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)
                        pytest_assert(False, stat_message)

                    if result is False and iteration < 4:
                        verify_again = True
                        time.sleep(3)

            if verify_again is False:
                break

            sleep(3)

    except Exception as errMsg:
        logger.info('verify_line_rate exception handling: calling stop_traffic ...')
        stop_traffic(snappi_api, control_state_obj)
        delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)
        pytest_assert(False, f'verify_line_rate: FAILED: {traceback.format_exc(None, errMsg)}')


def verify_line_rate_tc_5(Common_vars, duthosts, snappi_api, control_state_obj):
    """
    For test case 2.5

    2 tx-ports transmitting DSCP 1,2,3,4
    A total of 8 traffic items
    Add Rx L1 Rate (Gbps) Queued ID 1 from port 1 & 2. Should add up to 25
    Add Rx L1 Rate (Gbps) Queued ID 2 from port 1 & 2. Should add up to 25
    Add Rx L1 Rate (Gbps) Queued ID 3 from port 1 & 2. Should add up to 25
    Add Rx L1 Rate (Gbps) Queued ID 4 from port 1 & 2. Should add up to 25

    The proportion of traffic from each queue must match the configured weights within a 2% tolerance
        Queue 1: 23-27% (23-27 Gbps)
        Queue 2: 23-27% (23-27 Gbps)
        Queue 3: 23-27% (23-27 Gbps)
        Queue 4: 23-27% (23-27 Gbps)
    """
    selected_view_columns = ['Tx Port', 'Rx Port', 'Traffic Item', 'Tx L1 Rate (Gbps)',
                             'Egress Tracking', 'Rx L1 Rate (Gbps)']
    stats = {}

    try:
        # Test case success criteria
        low_range = 23
        high_range = 27

        # Use range(1,4) to verify stats up to 3 times for stat correctness.
        # Sometimes the stat's snapshot line rate is a bit too low. Check again for up to 3x.
        for iteration in range(1, 4):
            verify_again = False

            flow_stats = get_statistics(snappi_api,
                                        stat_view_name=Common_vars.egress_stat_view_name,
                                        stat_view_columns=selected_view_columns,
                                        show_tabulated_table=True)

            for rowNumber, flow in enumerate(flow_stats):
                # {'Tx Port': 'Port_2', 'Rx Port': 'Port_1', 'Traffic Item': 'sonic-s6100-dut1:Ethernet1
                #  Speed:100 QID:1 TC:1 DSCP:1 scheduler.7 WT:25 TTl_WT:100 Line_Rate:50 Expected_Rx_Gbps_Rate%:25',
                #  'Tx L1 Rate (Gbps)': '50.000', 'Egress Tracking': 'Custom: (2 bits at offset 126)',
                # 'Rx L1 Rate (Gbps)': '25.000'}
                if not flow['Traffic Item']:
                    continue

                if flow['Traffic Item'] != '':
                    tx_port = flow['Tx Port']
                    rx_port = flow['Rx Port']

                    stats.update({rowNumber: {'tx_port': tx_port,
                                              'rx_port': rx_port,
                                              'rx_line_rate': float(flow["Rx L1 Rate (Gbps)"])}})

            """
            Notes: Egress_Stats have 3 stat rows per flow.  Therefore, 0, 3, 6 ...
            stats:
                {0:  {'tx_port': 'Port_2', 'rx_port': 'Port_1', 'rx_line_rate': 12},
                 3:  {'tx_port': 'Port_2', 'rx_port': 'Port_1', 'rx_line_rate': 16},
                 6:  {'tx_port': 'Port_2', 'rx_port': 'Port_1', 'rx_line_rate': 9},
                 9:  {'tx_port': 'Port_2', 'rx_port': 'Port_1', 'rx_line_rate': 12},
                 12: {'tx_port': 'Port_3', 'rx_port': 'Port_1', 'rx_line_rate': 12},
                 15: {'tx_port': 'Port_3', 'rx_port': 'Port_1', 'rx_line_rate': 10},
                 18: {'tx_port': 'Port_3', 'rx_port': 'Port_1', 'rx_line_rate': 16},
                 21: {'tx_port': 'Port_3', 'rx_port': 'Port_1', 'rx_line_rate': 13}
                }
            """

            flow_1_results = round(float(stats[0]['rx_line_rate'] + stats[12]['rx_line_rate']))
            flow_2_results = round(float(stats[3]['rx_line_rate'] + stats[15]['rx_line_rate']))
            flow_3_results = round(float(stats[6]['rx_line_rate'] + stats[18]['rx_line_rate']))
            flow_4_results = round(float(stats[9]['rx_line_rate'] + stats[21]['rx_line_rate']))

            failed_messages = []

            message = (f"Flow_1 & 5 stats combined: {stats[0]['rx_line_rate']}Gbps + {stats[12]['rx_line_rate']}Gbps = "
                       f"{flow_1_results}  Acceptable-Range:{low_range}-{high_range} {iteration}/3x")
            if (flow_1_results >= low_range) and (flow_1_results <= high_range) is False:
                logger.info(f'FAILED: {message}')
                verify_again = True
                failed_messages.append(message)
            else:
                logger.info(f'PASSED: {message}')

            message = (f"Flow_2 & 6 stats combined: {stats[3]['rx_line_rate']}Gbps + {stats[15]['rx_line_rate']}Gbps = "
                       f"{flow_2_results}  Acceptable-Range:{low_range}-{high_range} {iteration}/3x")
            if (flow_2_results >= low_range) and (flow_2_results <= high_range) is False:
                logger.info(f'FAILED: {message}')
                verify_again = True
                failed_messages.append(message)
            else:
                logger.info(f'PASSED: {message}')

            message = (f"Flow_3 & 7 stats combined: {stats[6]['rx_line_rate']}Gbps + {stats[18]['rx_line_rate']}Gbps = "
                       f"{flow_3_results}  Acceptable-Range:{low_range}-{high_range} {iteration}/3x")
            if (flow_3_results >= low_range) and (flow_3_results <= high_range) is False:
                logger.info(f'FAILED: {message}')
                verify_again = True
                failed_messages.append(message)
            else:
                logger.info(f'PASSED: {message}')

            message = (f"Flow_4 & 8 stats combined: {stats[9]['rx_line_rate']}Gbps + {stats[21]['rx_line_rate']}Gbps = "
                       f"{flow_4_results}  Acceptable-Range:{low_range}-{high_range} {iteration}/3x")
            if (flow_4_results >= low_range) and (flow_4_results <= high_range) is False:
                logger.info(f'FAILED: {message}')
                verify_again = True
                failed_messages.append(message)
            else:
                logger.info(f'PASSED: {message}')

            if verify_again is False:
                break
            else:
                if iteration < 4:
                    sleep(3)

                if iteration == 3:
                    logger.info('verify_line_rate_tc_5: calling stop_traffic ...')
                    stop_traffic(snappi_api, control_state_obj)
                    delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)
                    pytest_assert(False, f'Test case 2.5 failed. {failed_messages}')

    except Exception as errMsg:
        logger.info('verify_line_rate_tc_5 exception handling: calling stop_traffic ...')
        stop_traffic(snappi_api, control_state_obj)
        delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)
        pytest_assert(False, f'Test case 2.5 error: {traceback.format_exc(None, errMsg)}')


def verify_line_rate_tc_6(Common_vars, duthosts, snappi_api, control_state_obj):
    """
    For test case 2.6

    2 tx-ports transmitting same round-robin DSCP 1,2,3,4
    A total of 8 traffic items
    Add Rx L1 Rate (Gbps) Queued ID 1 from port 1 & 2. Should add up to 25
    Add Rx L1 Rate (Gbps) Queued ID 2 from port 1 & 2. Should add up to 25
    Add Rx L1 Rate (Gbps) Queued ID 3 from port 1 & 2. Should add up to 25
    Add Rx L1 Rate (Gbps) Queued ID 4 from port 1 & 2. Should add up to 25

    The proportion of traffic from each queue must match the configured weights within a 2% tolerance
    Queue 1: 28-32% (28-32 Gbps)
    Queue 2: 38-42% (38-42 Gbps)
    Queue 3: 13-17% (13-17 Gbps)
    Queue 4: 13-17% (13-17 Gbps)
    """
    selected_view_columns = ['Tx Port', 'Rx Port', 'Flow Group', 'Tx L1 Rate (bps)', 'Rx L1 Rate (bps)']
    stats = {}

    try:
        flow_1_low_range = convert_number_to_gigabits(28)
        flow_1_high_range = convert_number_to_gigabits(32)
        flow_2_low_range = convert_number_to_gigabits(38)
        flow_2_high_range = convert_number_to_gigabits(42)
        flow_3_low_range = convert_number_to_gigabits(13)
        flow_3_high_range = convert_number_to_gigabits(17)
        flow_4_low_range = convert_number_to_gigabits(13)
        flow_4_high_range = convert_number_to_gigabits(17)

        # Use range(1,4) to verify stats up to 3 times for stat correctness.
        # Sometimes the stat's snapshot line rate is a bit too low. Check again for up to 3x.
        for iteration in range(1, 4):
            verify_again = False

            flow_stats = get_statistics(snappi_api,
                                        stat_view_name='Flow Statistics',
                                        stat_view_columns=selected_view_columns,
                                        show_tabulated_table=True)

            for rowNumber, flow in enumerate(flow_stats):
                # flow: {'Tx Port': 'Port_2', 'Rx Port': 'Port_1', 'Flow Group':
                #        'DUT_Name:sonic-s6100-dut1 Ethernet1 Speed:100Gbps QID:1 TC:1 DSCP:1
                #         scheduler.5 WT:30 Line_Rate:70 Expected_Rx_Gbps_Rate%:30',
                #        'Tx L1 Rate (bps)': '49999998720.000', 'Rx L1 Rate (bps)': '14948829120.000'}
                #
                # Problem: Regenerate resets the flow group name
                # flow: {'Tx Port': 'Port_2', 'Rx Port': 'Port_1', 'Flow Group': 'SrcPort:
                #         Ethernet1-EndpointSet-1 - Flow Group 0001',
                #        'Tx L1 Rate (bps)': '33333338560.000', 'Rx L1 Rate (bps)': '7888727040.000'}
                tx_port = flow['Tx Port']
                rx_port = flow['Rx Port']
                # tx_l1_rate = int(round(float(flow['Tx L1 Rate (bps)'])))
                rx_l1_rate = int(round(float(flow['Rx L1 Rate (bps)'])))
                traffic_item = flow['Flow Group']
                current_traffic_item = traffic_item

                # DUT_Name:sonic-s6100-dut1 Ethernet1 Speed:100Gbps QID:4 TC:4 DSCP:4
                # scheduler.6 WT:15 Line_Rate:70 Expected_Rx_Gbps_Rate%:30-EndpointSet-1 - Flow Group 0001
                # expected_rx_line_rate = int(traffic_item.split(' ')[-1].split(':')[1])
                regex_weight = search('.* WT:([0-9]+) +', current_traffic_item)
                flow_weight = int(regex_weight.group(1))
                regex_port_speed = search('.* Speed:([0-9]+)', current_traffic_item)
                port_speed = int(regex_port_speed.group(1))

                # percentage_whole_number = int("%.0f" % (Common_vars.pass_threshold_pct * 100))
                # 100 x .02 = 2
                acceptable_threshold = port_speed * Common_vars.pass_threshold_pct
                # If weight=40, 40-2=38 (low).  40+2=42 (high)
                traffic_flow_pass_criteria_low = round(flow_weight - acceptable_threshold)
                traffic_flow_pass_criteria_high = round(flow_weight + acceptable_threshold)

                stats.update({rowNumber: {'rx_line_rate': rx_l1_rate}})

                if is_at_least_one_gigabit(rx_l1_rate) is False:
                    message = (f'tx-port:{tx_port} rx-port:{rx_port} '
                               f'expecting between range:'
                               f'{traffic_flow_pass_criteria_low}-{traffic_flow_pass_criteria_high} '
                               f'Gbps.  Received > 1 Gbps: {rx_l1_rate}')
                    pytest_assert(False, message)

            flow_1_results = round(float(stats[0]['rx_line_rate'] + stats[4]['rx_line_rate']))
            flow_2_results = round(float(stats[1]['rx_line_rate'] + stats[5]['rx_line_rate']))
            flow_3_results = round(float(stats[2]['rx_line_rate'] + stats[6]['rx_line_rate']))
            flow_4_results = round(float(stats[3]['rx_line_rate'] + stats[7]['rx_line_rate']))

            """
            {
                0: {'tx_port': 'Port_2', 'rx_port': 'Port_1', 'rx_line_rate': 14517714560,
                    'min': 28000000000, 'max': 32000000000},
                1: {'tx_port': 'Port_3', 'rx_port': 'Port_1', 'rx_line_rate': 20227868160,
                    'min': 38000000000, 'max': 42000000000},
                2: {'tx_port': 'Port_4', 'rx_port': 'Port_1', 'rx_line_rate': 7630302720,
                    'min': 13000000000, 'max': 17000000000},
                3: {'tx_port': 'Port_5', 'rx_port': 'Port_1', 'rx_line_rate': 7614938560,
                    'min': 13000000000, 'max': 17000000000},
                4: {'tx_port': 'Port_2', 'rx_port': 'Port_1', 'rx_line_rate': 14482499200,
                    'min': 28000000000, 'max': 32000000000},
                5: {'tx_port': 'Port_3', 'rx_port': 'Port_1', 'rx_line_rate': 20337739840,
                    'min': 38000000000, 'max': 42000000000},
                6: {'tx_port': 'Port_4', 'rx_port': 'Port_1', 'rx_line_rate': 7586891520,
                    'min': 13000000000, 'max': 17000000000},
                7: {'tx_port': 'Port_5', 'rx_port': 'Port_1', 'rx_line_rate': 7602255680,
                    'min': 13000000000, 'max': 17000000000}
            }

            PASSED: Flow_1_Rx:10000000192 & Flow_5_Rx:9999999848
                    Rx_Combined:20000000040/Gbps
                    Acceptable_Range:28000000000-32000000000 2/3x

            PASSED: Flow_2_Rx:10000000192 & Flow_5_Rx:10000000192
                    Rx_Combined:20000000384/Gbps
                    Acceptable_Range:38000000000-42000000000 2/3x

            FAILED: Flow_3_Rx:9999999848  & Flow_5_Rx:10000000192
                    Rx_Combined:20000000040/Gbps
                    Acceptable_Range:13000000000-17000000000 2/3x

            FAILED: Flow_4_Rx:9999999848  & Flow_5_Rx:9999999848
                    Rx_Combined:19999999696/Gbps
                    Acceptable_Range:13000000000-17000000000 2/3x
            """
            failed_messages = []

            message = (f'Flow_1_Rx:{stats[0]["rx_line_rate"]} & Flow_5_Rx:{stats[4]["rx_line_rate"]} '
                       f'Rx_Combined:{flow_1_results}/Gbps  Acceptable_Range:{flow_1_low_range}-{flow_1_high_range} '
                       f'{iteration}/3x')

            if (flow_1_results >= flow_1_low_range) and (flow_1_results <= flow_1_high_range) is False:
                logger.info(f'FAILED: {message}')
                failed_messages.append(message)
                verify_again = True
            else:
                logger.info(f'PASSED: {message}')

            message = (f'Flow_2_Rx:{stats[1]["rx_line_rate"]} & Flow_5_Rx:{stats[5]["rx_line_rate"]} '
                       f'Rx_Combined:{flow_2_results}/Gbps  Acceptable_Range:{flow_2_low_range}-{flow_2_high_range} '
                       f'{iteration}/3x')

            if (flow_1_results >= flow_2_low_range) and (flow_2_results <= flow_2_high_range) is False:
                logger.info(f'FAILED: {message}')
                failed_messages.append(message)
                verify_again = True
            else:
                logger.info(f'PASSED: {message}')

            message = (f'Flow_3_Rx:{stats[2]["rx_line_rate"]} & Flow_5_Rx:{stats[6]["rx_line_rate"]} '
                       f'Rx_Combined:{flow_3_results}/Gbps  Acceptable_Range:{flow_3_low_range}-{flow_3_high_range} '
                       f'{iteration}/3x')

            if (flow_1_results >= flow_3_low_range) and (flow_3_results <= flow_3_high_range) is False:
                logger.info(f'FAILED: {message}')
                failed_messages.append(message)
                verify_again = True
            else:
                logger.info(f'PASSED: {message}')

            message = (f'Flow_4_Rx:{stats[3]["rx_line_rate"]} & Flow_5_Rx:{stats[7]["rx_line_rate"]} '
                       f'Rx_Combined:{flow_4_results}/Gbps  Acceptable_Range:{flow_4_low_range}-{flow_4_high_range} '
                       f'{iteration}/3x')
            if (flow_1_results >= flow_4_low_range) and (flow_4_results <= flow_4_high_range) is False:
                logger.info(f'FAILED: {message}')
                failed_messages.append(message)
                verify_again = True
            else:
                logger.info(f'PASSED: {message}')

            if verify_again is False:
                break
            else:
                if iteration < 4:
                    logger.info(f'Reviewing stats again {iteration}/3x')
                    sleep(3)

                if iteration == 3:
                    logger.info('verify_line_rate_tc_6: calling stop_traffic ...')
                    stop_traffic(snappi_api, control_state_obj)
                    delete_flows(Common_vars, snappi_api, remove_egress_stat_view=False)
                    pytest_assert(False, f'Test case 2.6 failed: {failed_messages}')

    except Exception as errMsg:
        pytest_assert(False, f'Test case 2.6 error: {traceback.format_exc(None, errMsg)}')


def verify_frames(Common_vars, duthosts, snappi_api, control_state_obj, pkt_sequence_checking_enabled=False):
    """
    Get DUT egress stats and compare with traffic generator's rx stats
    """
    # read_dut_egress_stats_once = True
    current_traffic_item = ''
    selected_view_columns = ['Tx Port', 'Rx Port', 'Traffic Item', 'Egress Tracking', 'Tx Frames', 'Rx Frames']
    if pkt_sequence_checking_enabled:
        selected_view_columns += ['Small Error', 'Big Error', 'Reverse Error', 'Last Sequence Number']

    flow_stats = get_statistics(snappi_api,
                                stat_view_name=Common_vars.egress_stat_view_name,
                                stat_view_columns=selected_view_columns,
                                show_tabulated_table=True)

    try:
        get_dut_wred_stats(Common_vars, duthosts)

        for flow in flow_stats:
            # {'Tx Port': 'Port_2', 'Rx Port': 'Port_1',
            # 'Traffic Item': 'DUT_Name:sonic-s6100-dut1 Ethernet1 Speed:100Gbps QID:1 TC:1
            # DSCP:1 scheduler.7 WT:25 Line_Rate:24 Expected_Rx_Gbps_Rate%:25',
            # 'Egress Tracking': 'Custom: (2 bits at offset 126)', 'Tx Frames': '52349032',
            # 'Rx Frames': '52349032', 'Small Error': '0', 'Big Error': '0', 'Reverse Error': '0',
            # 'Last Sequence Number': '52349031'}

            egress_stats = flow['Egress Tracking']

            if flow['Traffic Item'] != '':
                tx_frames = int(flow['Tx Frames'])
                current_traffic_item = flow['Traffic Item']
                regex_traffic_item = search('.*QID:([0-9]+) +', current_traffic_item)
                tx_port_queue_id = int(regex_traffic_item.group(1))
                regex_weight = search('.* WT:([0-9]+) +', current_traffic_item)
                flow_weight = int(regex_weight.group(1))
                regex_duthost = search('.*DUT_Name:([^ ]+) +', current_traffic_item)
                dut_host_name = regex_duthost.group(1)

                if pkt_sequence_checking_enabled:
                    rx_frames = int(flow['Rx Frames'])
                    small_error = int(flow['Small Error'])
                    big_error = int(flow['Big Error'])
                    reverse_error = int(flow['Reverse Error'])
                    last_sequence_number = int(flow['Last Sequence Number'])

                    """
                    Small error means:    The packets sequence number out of order is within
                                          the given threshold
                    Big error means:      Out of sequence is greater than the threshold
                    Reverse order means:  The received packet's sequence number is lesser than
                                          already received packet
                    last_sequence_number: Releasing packets from the buffer: The receiver releases
                                          the stored packets in order once the "last sequence number"
                                          has been received.

                                            For example, in the sequence P1, P3, P2, P4, once P2 arrives,
                                            the buffer will release P2 and then P3 to the application,
                                            with the "last sequence number" now being 4.
                                            So, if tx_frames == last_sequence_number, this is passed.
                                            Otherwise, some packets were not reassembled.
                    """
                    message = (f'Packet sequence checking: Small_Error:  Tx_Frames:{tx_frames} -> '
                               f'Rx_Frames:{rx_frames} {small_error} Big_Error:{big_error} '
                               f'Reverse_Error:{reverse_error}  Last_Sequence_Number:{last_sequence_number}')
                    logger.info(message)

                    # Success criteria.  If any of the below stats > 0, means packets were out of sequence.
                    # Test case 2.8 sends at 97% line rate. Expecting no out of sequence packets.
                    # Only if line rate is 100% will have packets out of sequence.
                    if small_error > 0 or big_error > 0 or reverse_error > 0:
                        logger.info('verify_frames: calling stop_traffic ...')
                        stop_traffic(snappi_api, control_state_obj)
                        delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)
                        message = (f'pkt_sequence_checking_enabled:{pkt_sequence_checking_enabled}. '
                                   f'Detected packets out of sequence: {message}')
                        pytest_assert(False, message)

            # Only care for custom bit 3 on rx stats:
            # Not every flow stat line has traffic item and traffic item line always come first
            if pkt_sequence_checking_enabled is False:
                if egress_stats != '' and egress_stats == "3":
                    rx_frames = int(flow['Rx Frames'])
                    Common_vars.tgen_flow_stats[dut_host_name][tx_port_queue_id].update({'rx_frames': rx_frames,
                                                                                         'tx_frames': tx_frames})

        # Compare and verify DUT Egress stats + Tgen Rx stats
        # Common_vars.tgen_flow_stats:
        #     {'sonic-s6100-dut1': {1: {'egressPackets': 1041774, 'rx_frames': 1041774, 'tx_frames': 64400986},
        #                           2: {'egressPackets': 32212705, 'rx_frames': 32212705, 'tx_frames': 64400986},
        #                           3: {'egressPackets': 2936223, 'rx_frames': 2936223, 'tx_frames': 64400986},
        #                           4: {'egressPackets': 32219979, 'rx_frames': 32219979, 'tx_frames': 64400986}
        #                          }
        if pkt_sequence_checking_enabled is False:
            for dut_host in duthosts:
                for tx_queue_id, properties in Common_vars.tgen_flow_stats[dut_host.hostname].items():
                    dwrr_wred_rx_frames_pct_on_custome_bit_3 = (properties["rx_frames"] / properties['tx_frames'])*100
                    flow_weight = Common_vars.get_queue_id_weight[dut_host.hostname][tx_queue_id]
                    allowed_loss_threshold = round(abs(flow_weight - (flow_weight*Common_vars.pass_threshold_pct)), 2)

                    # Verifying Frames Egress Queue: 1:  WT:100  allowed_loss_threshold:98.0
                    # DUT_EgressPkts: 32064555  RxPkets: 32065944. rx_percentage: 50.02087820754411
                    message = (
                        f'Verifying egress ECN packets:  Queue: {tx_queue_id}: '
                        f'Weight:{flow_weight}  TxFrames:{properties["tx_frames"]} '
                        f'allowed_loss_threshold:{allowed_loss_threshold}  '
                        f'DUT_EgressPkts:{properties["egressPackets"]}  RxPkts:{properties["rx_frames"]} '
                        f'rx_percentage:{dwrr_wred_rx_frames_pct_on_custome_bit_3}'
                    )
                    logger.info(message)

                    message = (f'Verifying egress ECN packets:  Queue: {tx_queue_id}: '
                               f'egressPkts:{properties["egressPackets"]} != rxPkts:{properties["rx_frames"]}')
                    pytest_assert(properties['egressPackets'] == properties['rx_frames'], message)

    except Exception as errMsg:
        logger.info('verify_frames exception handling: calling stop_traffic ...')
        stop_traffic(snappi_api, control_state_obj)
        delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)
        pytest_assert(False, f'verify_frames: FAILED: {traceback.format_exc(None, errMsg)}')
