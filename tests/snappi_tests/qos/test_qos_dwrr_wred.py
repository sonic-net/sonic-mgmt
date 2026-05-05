"""
TEST PLAN: DWRR

STEPS:
    - Make copy of config_db.json file to restore at the end of testing
    - Each test case modifies Ethernet interface queue ID scheduler/weight
      according to the test case requirements
    - Saves the configurations to the config_db.json file
    - Reloads the DUT

    Tested with:
        - Build SONiC.20241211.45
        - Frame size 1500

    - Restore original copy of config_db.json
"""

import logging
import pytest
from time import sleep
# from rich import print as pr

from tests.snappi_tests.qos.files.qos_priority_helper import initiate_snappi_port_groups_dict
from tests.snappi_tests.qos.files.qos_priority_helper import define_rx_tx_ports
from tests.snappi_tests.qos.files.qos_priority_helper import read_dut_qos_configurations
from tests.snappi_tests.qos.files.qos_priority_helper import create_snappi_flows
from tests.snappi_tests.qos.files.qos_priority_helper import config_snappi_egress_tracking_wred

from tests.snappi_tests.qos.files.qos_priority_helper import clear_dut_stat_counters, run_traffic
from tests.snappi_tests.qos.files.qos_priority_helper import map_scheduler_id_by_weight, save_dut_config
from tests.snappi_tests.qos.files.qos_priority_helper import reload_dut, verify_dut_ports_up, backup_config_db

from tests.snappi_tests.qos.files.qos_priority_helper import restore_config_db, stop_traffic
from tests.snappi_tests.qos.files.qos_priority_helper import delete_flows, verify_line_rate
from tests.snappi_tests.qos.files.qos_priority_helper import verify_line_rate_tc_5, verify_line_rate_tc_6
from tests.snappi_tests.qos.files.qos_priority_helper import verify_frames

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts # noqa F401
from tests.common.fixtures.conn_graph_facts import fanout_graph_facts, fanout_graph_facts_multidut # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api, get_snappi_ports, get_snappi_ports_single_dut # noqa F401
from tests.common.snappi_tests.snappi_fixtures import get_snappi_ports_multi_dut, snappi_testbed_config # noqa F401
from tests.snappi_tests.dataplane.files.helper import get_duthost_interface_details
from tests.snappi_tests.dataplane.files.helper import set_primary_chassis, create_snappi_config # noqa F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.snappi_helpers import wait_for_arp

logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('tgen')]


class Common_vars:
    # User defined variables
    config_db_file = '/etc/sonic/config_db.json'
    # Frame size cannot be 1500. Will have inconsistent success/failure
    frame_size = 1500
    flow_duration_seconds = 60
    pass_threshold_pct = .02

    # --- DON'T TOUCH BELOW VALUES ---

    # Options: dwrr | dwrr+wred
    type_of_test = 'dwrr+wred'
    traffic_flows = []
    snappi_port_groups = {}
    port_group_range = {}
    dut_qos_configs = {}

    # For inter-port testing
    total_port_groups = 0
    # For read_dut_qos_configurations. Which queue ID to begin at.
    tx_port_starting_queue_id = 1
    # Save current dut interface queue id scheduler id to restore after testing
    current_int_scheduler_id = {}
    # For verify_dut_ports_up
    tx_port_names_for_verify_port_up = ''
    # Get the queue ID's weight for verify passed/failed traffic
    get_queue_id_weight = {}
    # Store dut egress stats and tgen rx stats to compare for pass/fail
    tgen_flow_stats = {}
    # The amount of endpoints per flow: single | multiple.  TC 2.6 uses multiple
    flows_per_port = 'single'
    # Enable dut queue stat counters. WRED testing.
    dut_queue_stat_counters = []
    get_dscp_from_traffic_class = {}
    # For dwrr+wred test cases
    # Use the weight to get the scheduleId for Ethernet interface queue IDs
    scheduler_to_weight_dict = {}
    weight_to_scheduler_dict = {}
    # Used in config_int_queue_id_scheduler_id
    # Save Ethernet interface's queue_id and scheduler_id
    tx_port_flow_configs = {}
    # IPv4 | IPv6: This will automatically get updated
    subnet_type = 'IPv4'
    egress_statview_obj = None
    egress_stat_view_name = 'Egress Stats'
    dut_hosts = []
    # Backup and restore the original config_db.json file at the end of this script
    backup_config_db = False
    backup_config_db_file = f'/tmp/{config_db_file.split("/")[-1]}_backup'


@pytest.fixture(scope="session")
def local_script_setup_and_teardown():
    logger.info("Setup before ALL test cases")
    yield
    logger.info("Teardown after ALL test cases")
    restore_config_db(Common_vars)
    
    
def execute_common_configs(duthosts,
                           create_snappi_config, # noqa F811
                           snappi_api, # noqa F811
                           get_snappi_ports, # noqa F811
                           subnet_type,
                           flow_configs,
                           config_egress_tracking=True,
                           enable_pkt_sequence_checking=False):
    snappi_extra_params = SnappiTestParams()
    snappi_ports = get_duthost_interface_details(duthosts, get_snappi_ports,
                                                 subnet_type, protocol_type='ip')
    tx_ports = [snappi_ports[0]]
    rx_ports = snappi_ports[1:]

    snappi_extra_params.protocol_config = {
        "Tx": {"protocol_type": "ip", "is_rdma": True, "ports": tx_ports, "subnet_type": subnet_type},
        "Rx": {"protocol_type": "ip", "is_rdma": True, "ports": rx_ports, "subnet_type": subnet_type},
    }

    Common_vars.dut_hosts = duthosts

    # These test cases uses just one DUT.
    # So, just backup from the first DUT and restore at the end of the script.
    for duthost in duthosts:
        if Common_vars.backup_config_db is False:
            backup_config_db(Common_vars, duthost)
            Common_vars.backup_config_db = True
                
        # scheduler_data_dict: Get the scheduler_id from the weight
        # weight_data_dict:    Get the weight from the scheduler_id
        Common_vars.scheduler_to_weight_dict, Common_vars.weight_to_scheduler_dict = \
            map_scheduler_id_by_weight(duthost)

    initiate_snappi_port_groups_dict(Common_vars, duthosts, snappi_ports)
    read_dut_qos_configurations(Common_vars, duthosts[0])
    define_rx_tx_ports(Common_vars, snappi_ports, flow_configs)
    save_dut_config(duthosts[0], Common_vars.config_db_file)
    reload_dut(duthosts[0], Common_vars.config_db_file)
    verify_dut_ports_up(duthosts[0], Common_vars.tx_port_names_for_verify_port_up)

    # Create a dict for creating Topologies and traffic flows
    snappi_config, snappi_obj_handles = create_snappi_config(snappi_extra_params)
    # Execute the topology configs
    snappi_api.set_config(snappi_config)

    logger.info('Wait for Arp to Resolve ...')
    if wait_for_arp(snappi_api, max_attempts=10, poll_interval_sec=2) != 0:
        pytest_assert(False, "ARP failed")

    snappi_configs = create_snappi_flows(Common_vars,
                                         duthosts,
                                         snappi_config,
                                         snappi_api,
                                         snappi_ports,
                                         traffic_duration=Common_vars.flow_duration_seconds,
                                         enable_pkt_sequence_checking=enable_pkt_sequence_checking)

    if config_egress_tracking:
        config_snappi_egress_tracking_wred(Common_vars,
                                           duthosts,
                                           snappi_api,
                                           egress_encapsulation='Any: Use Custom Settings',
                                           egress_custom_offset_bits=126,
                                           egress_width_bits=2,
                                           egress_offset="Custom",
                                           egress_stat_view_name=Common_vars.egress_stat_view_name)

    clear_dut_stat_counters(duthosts)

    logger.info(f'Running traffic for {Common_vars.flow_duration_seconds} seconds ...')
    control_state_obj = run_traffic(Common_vars, duthosts, snappi_api=snappi_api, config=snappi_configs)
    sleep(Common_vars.flow_duration_seconds)
    logger.info('Run traffic completed')
    return control_state_obj


@pytest.mark.parametrize("subnet_type", ["IPv4"])
def test_dwrr_wred_with_extreme_weight_ratio_1(snappi_api,                 # noqa F811
                                               conn_graph_facts,           # noqa F811
                                               fanout_graph_facts_multidut, # noqa F811
                                               duthosts,
                                               set_primary_chassis, # noqa F811
                                               rand_one_dut_hostname,
                                               rand_one_dut_portname_oper_up,
                                               get_snappi_ports, # noqa F811
                                               subnet_type, # noqa F811 
                                               create_snappi_config, # noqa F811
                                               local_script_setup_and_teardown
                                               ):
    """
    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        setup_snappi_port_configs (pytest fixture): Returns a list of dicts
            containing all snappi port srcIp, gateways, duthost, etc
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'

    Returns:
        N/A
    """
    # TC 2.1:
    # 2 Tx-Ports:
    #       Note: Test case states to transmit 60% line rate, but this is incorrect.
    #             The CE bit won't change from ingressing bit2 to egressing bit 3.
    #             Line rate must be higher than the weight.
    #             Otherwise, the Sonic DUT doesn't transmit frames out of CE bit 3
    #             and this script verifies packets on CE bit 3.
    Common_vars.flows_per_port = 'single'
    flow_configs = {'test_case': '2.1',
                    'total_tx_ports': 2,
                    'weight_distribution_type': 'sequential',
                    'tx_port_flows': [{'queue_id': 1, 'weight': 60, 'line_rate': 70,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 60},
                                      {'queue_id': 2, 'weight': 40, 'line_rate': 60,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 40}]}

    Common_vars.subnet_type = subnet_type

    # Avoid egress tracking for test case 2.6 because of flow name getting reset and need to be renamed
    control_state_obj = execute_common_configs(duthosts, create_snappi_config, snappi_api,
                                               get_snappi_ports, subnet_type,
                                               flow_configs, config_egress_tracking=True,
                                               enable_pkt_sequence_checking=False)
    verify_line_rate(Common_vars, duthosts, snappi_api, control_state_obj)
    stop_traffic(snappi_api, control_state_obj)
    # For TC 2.1-2.4 only
    verify_frames(Common_vars, duthosts, snappi_api, control_state_obj, pkt_sequence_checking_enabled=False)
    delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)


@pytest.mark.parametrize("subnet_type", ["IPv4"])
def test_dwrr_wred_with_extreme_weight_ratio_2(snappi_api,                 # noqa F811
                                               conn_graph_facts,            # noqa F811
                                               fanout_graph_facts_multidut, # noqa F811
                                               duthosts,
                                               set_primary_chassis, # noqa F811
                                               rand_one_dut_hostname,
                                               rand_one_dut_portname_oper_up,
                                               get_snappi_ports, # noqa F811
                                               subnet_type, # noqa F811 
                                               create_snappi_config, # noqa F811
                                               local_script_setup_and_teardown
                                               ):
    # TC 2.2:
    # 2 Tx-Ports
    #       Note: Test case requirement using line rate = 70% won't work. The CE bit won't change from 2 to 3.
    Common_vars.flows_per_port = 'single'
    flow_configs = {'test_case': '2.2',
                    'total_tx_ports': 2,
                    'weight_distribution_type': 'sequential',
                    'tx_port_flows': [{'queue_id': 1, 'weight': 95, 'line_rate': 100,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 95},
                                      {'queue_id': 2, 'weight': 5,  'line_rate': 100,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 5}]}

    Common_vars.subnet_type = subnet_type

    # Avoid egress tracking for test case 2.6 because of flow name getting reset and need to be renamed
    control_state_obj = execute_common_configs(duthosts, create_snappi_config, snappi_api,
                                               get_snappi_ports, subnet_type,
                                               flow_configs, config_egress_tracking=True,
                                               enable_pkt_sequence_checking=False)
    verify_line_rate(Common_vars, duthosts, snappi_api, control_state_obj)
    stop_traffic(snappi_api, control_state_obj)

    # Verify DUT tx-frames and snappi egress rx-frames
    # For TC 2.1-2.4 only
    verify_frames(Common_vars, duthosts, snappi_api, control_state_obj, pkt_sequence_checking_enabled=False)
    delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)


@pytest.mark.parametrize("subnet_type", ["IPv4"])
def test_dwrr_wred_with_extreme_weight_ratio_3(snappi_api,                 # noqa F811
                                               conn_graph_facts,           # noqa F811
                                               fanout_graph_facts_multidut, # noqa F811
                                               duthosts,
                                               set_primary_chassis, # noqa F811
                                               rand_one_dut_hostname,
                                               rand_one_dut_portname_oper_up,
                                               get_snappi_ports, # noqa F811 
                                               subnet_type, # noqa F811 
                                               create_snappi_config, # noqa F811
                                               local_script_setup_and_teardown
                                               ):
    # TC 2.3:
    # 3 Tx-Ports
    Common_vars.flows_per_port = 'single'
    flow_configs = {'test_case': '2.3',
                    'total_tx_ports': 3,
                    'weight_distribution_type': 'sequential',
                    'tx_port_flows': [{'queue_id': 1, 'weight': 30, 'line_rate': 50,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 30},
                                      {'queue_id': 2, 'weight': 40, 'line_rate': 50,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 40},
                                      {'queue_id': 3, 'weight': 30, 'line_rate': 50,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 30}]}

    Common_vars.subnet_type = subnet_type

    # Avoid egress tracking for test case 2.6 because of flow name getting reset and need to be renamed
    control_state_obj = execute_common_configs(duthosts, create_snappi_config, snappi_api,
                                               get_snappi_ports, subnet_type,
                                               flow_configs, config_egress_tracking=True,
                                               enable_pkt_sequence_checking=False)
    verify_line_rate(Common_vars, duthosts, snappi_api, control_state_obj)
    stop_traffic(snappi_api, control_state_obj)

    # Verify DUT tx-frames and snappi egress rx-frames
    # For TC 2.1-2.4 only
    verify_frames(Common_vars, duthosts, snappi_api, control_state_obj, pkt_sequence_checking_enabled=False)
    delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)


@pytest.mark.parametrize("subnet_type", ["IPv4"])
def test_dwrr_wred_with_extreme_weight_ratio_4(snappi_api,                 # noqa F811
                                               conn_graph_facts,           # noqa F811
                                               fanout_graph_facts_multidut, # noqa F811
                                               duthosts,
                                               set_primary_chassis, # noqa F811
                                               rand_one_dut_hostname,
                                               rand_one_dut_portname_oper_up,
                                               get_snappi_ports, # noqa F811
                                               subnet_type, # noqa F811
                                               create_snappi_config, # noqa F811
                                               local_script_setup_and_teardown
                                               ):
    # TC 2.4:
    # 4 Tx-Ports
    Common_vars.flows_per_port = 'single'
    flow_configs = {'test_case': '2.4',
                    'total_tx_ports': 4,
                    'weight_distribution_type': 'sequential',
                    'tx_port_flows': [{'queue_id': 1, 'weight': 30, 'line_rate': 35,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 30},
                                      {'queue_id': 2, 'weight': 40, 'line_rate': 45,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 40},
                                      {'queue_id': 3, 'weight': 15, 'line_rate': 25,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 15},
                                      {'queue_id': 4, 'weight': 15, 'line_rate': 25,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 15}]}

    Common_vars.subnet_type = subnet_type

    # Avoid egress tracking for test case 2.6 because of flow name getting reset and need to be renamed
    control_state_obj = execute_common_configs(duthosts, create_snappi_config, snappi_api,
                                               get_snappi_ports, subnet_type,
                                               flow_configs, config_egress_tracking=True,
                                               enable_pkt_sequence_checking=False)
    verify_line_rate(Common_vars, duthosts, snappi_api, control_state_obj)
    stop_traffic(snappi_api, control_state_obj)

    # Verify DUT tx-frames and snappi egress rx-frames
    # For TC 2.1-2.4 only
    verify_frames(Common_vars, duthosts, snappi_api, control_state_obj, pkt_sequence_checking_enabled=False)
    delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)


@pytest.mark.parametrize("subnet_type", ["IPv4"])
def test_dwrr_wred_with_extreme_weight_ratio_5(snappi_api,                 # noqa F811
                                               conn_graph_facts,           # noqa F811
                                               fanout_graph_facts_multidut, # noqa F811
                                               duthosts,
                                               set_primary_chassis, # noqa F811
                                               rand_one_dut_hostname,
                                               rand_one_dut_portname_oper_up,
                                               get_snappi_ports, # noqa F811
                                               subnet_type, # noqa F811
                                               create_snappi_config, # noqa F811
                                               local_script_setup_and_teardown
                                               ):

    Common_vars.subnet_type = subnet_type

    # TC 2.5:
    # 2 Tx-Ports
    # Each Tx-Port create 4 traffic flows. Each traffic flow sends different DSCP (T1=1, T2=2, T3=3, T4=4)
    # Each port common queue ID sending line rate equals to 40%
    # Packet sizes: 64, 512, 1024, 1500 bytes
    # Pass/Failed criteria: Add line-rate between port1 and port2 common queue IDs
    Common_vars.flows_per_port = 'single'
    flow_configs = {'test_case': '2.5',
                    'total_tx_ports': 2,
                    'weight_distribution_type': 'map_port_index_with_flow_index',
                    'tx_port_flows': [({'queue_id': 1, 'weight': 25, 'line_rate': 20,
                                        'frame_size': 64},
                                       {'queue_id': 2, 'weight': 25, 'line_rate': 25,
                                        'frame_size': 512},
                                       {'queue_id': 3, 'weight': 25, 'line_rate': 15,
                                        'frame_size': 1024},
                                       {'queue_id': 4, 'weight': 25, 'line_rate': 20,
                                        'frame_size': 1500}),
                                      ({'queue_id': 1, 'weight': 25, 'line_rate': 20,
                                        'frame_size': 64},
                                       {'queue_id': 2, 'weight': 25, 'line_rate': 15,
                                        'frame_size': 512},
                                       {'queue_id': 3, 'weight': 25, 'line_rate': 25,
                                        'frame_size': 1024},
                                       {'queue_id': 4, 'weight': 25, 'line_rate': 20,
                                        'frame_size': 1500})
                                      ]}

    # Avoid egress tracking for test case 2.6 because of flow name getting reset and need to be renamed
    control_state_obj = execute_common_configs(duthosts, create_snappi_config, snappi_api,
                                               get_snappi_ports, subnet_type,
                                               flow_configs, config_egress_tracking=True,
                                               enable_pkt_sequence_checking=False)
    verify_line_rate_tc_5(Common_vars, duthosts, snappi_api, control_state_obj)
    stop_traffic(snappi_api, control_state_obj)
    delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)


@pytest.mark.parametrize("subnet_type", ["IPv4"])
def test_dwrr_wred_with_extreme_weight_ratio_6(snappi_api,                 # noqa F811
                                               conn_graph_facts,           # noqa F811
                                               fanout_graph_facts_multidut, # noqa F811
                                               duthosts,
                                               set_primary_chassis, # noqa F811
                                               rand_one_dut_hostname,
                                               rand_one_dut_portname_oper_up,
                                               get_snappi_ports, # noqa F811
                                               subnet_type, # noqa F811
                                               create_snappi_config, # noqa F811
                                               local_script_setup_and_teardown
                                               ):
    Common_vars.subnet_type = subnet_type

    # TC 2.6:
    # 2 Tx-Ports
    # For each port: Create 1 traffic item with 4 endpoints round-robin DSCP 1,2,3,4
    Common_vars.flows_per_port = 'multiple'
    flow_configs = {'test_case': '2.6',
                    'total_tx_ports': 2,
                    'weight_distribution_type': 'all_flows_as_endpoint_flows_on_each_port',
                    'tx_port_flows': [{'queue_id': 1, 'weight': 30, 'line_rate': 70,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 30},
                                      {'queue_id': 2, 'weight': 40, 'line_rate': 70,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 40},
                                      {'queue_id': 3, 'weight': 15, 'line_rate': 70,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 15},
                                      {'queue_id': 4, 'weight': 15, 'line_rate': 70,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 15}]}

    # Avoid egress tracking for test case 2.6 because of flow name getting reset and need to be renamed
    control_state_obj = execute_common_configs(duthosts, create_snappi_config, snappi_api,
                                               get_snappi_ports, subnet_type,
                                               flow_configs, config_egress_tracking=False,
                                               enable_pkt_sequence_checking=False)
    verify_line_rate_tc_6(Common_vars, duthosts, snappi_api, control_state_obj)
    stop_traffic(snappi_api, control_state_obj)
    delete_flows(Common_vars, snappi_api, remove_egress_stat_view=False)


@pytest.mark.parametrize("subnet_type", ["IPv4"])
def test_dwrr_wred_with_extreme_weight_ratio_7_phase_1(snappi_api,                 # noqa F811
                                                       conn_graph_facts,           # noqa F811
                                                       fanout_graph_facts_multidut, # noqa F811
                                                       duthosts,
                                                       set_primary_chassis, # noqa F811
                                                       rand_one_dut_hostname,
                                                       rand_one_dut_portname_oper_up,
                                                       get_snappi_ports, # noqa F811
                                                       subnet_type, # noqa F811
                                                       create_snappi_config, # noqa F811
                                                       local_script_setup_and_teardown
                                                       ):
    Common_vars.subnet_type = subnet_type

    # TC 2.7:
    # 3 Tx-Ports (4-Phases)
    Common_vars.flows_per_port = 'single'
    # Phase 1:
    #    Weight: Port1=20 LR=30, Port2=50  LR=40, Port3=30  LR=40
    #    Port 2 will have dedicated 40G as it is below the configured weight
    #    Remaining is 60G and the weights configured for Port 1 and Port 3 are 20 & 30 respectively
    #    So to find out how much it will send:
    #       For port 1: 60 * 20/50 = 24
    #       For port 3: 60 * 30/50 = 36
    flow_configs = {'test_case': '2.7 phase 1',
                    'total_tx_ports': 3,
                    'weight_distribution_type': 'sequential',
                    'tx_port_flows': [{'queue_id': 1, 'weight': 20, 'line_rate': 30,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 24},
                                      {'queue_id': 2, 'weight': 50, 'line_rate': 40,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 40},
                                      {'queue_id': 3, 'weight': 30, 'line_rate': 40,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 36}]}

    # Avoid egress tracking for test case 2.6 because of flow name getting reset and need to be renamed
    control_state_obj = execute_common_configs(duthosts, create_snappi_config, snappi_api,
                                               get_snappi_ports, subnet_type,
                                               flow_configs, config_egress_tracking=True,
                                               enable_pkt_sequence_checking=False)
    verify_line_rate(Common_vars, duthosts, snappi_api, control_state_obj)
    stop_traffic(snappi_api, control_state_obj)
    delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)


@pytest.mark.parametrize("subnet_type", ["IPv4"])
def test_dwrr_wred_with_extreme_weight_ratio_7_phase_2(snappi_api,                 # noqa F811
                                                       conn_graph_facts,           # noqa F811
                                                       fanout_graph_facts_multidut, # noqa F811
                                                       duthosts,
                                                       set_primary_chassis, # noqa F811
                                                       rand_one_dut_hostname,
                                                       rand_one_dut_portname_oper_up,
                                                       get_snappi_ports, # noqa F811
                                                       subnet_type, # noqa F811
                                                       create_snappi_config, # noqa F811
                                                       local_script_setup_and_teardown
                                                       ):
    Common_vars.subnet_type = subnet_type

    # TC 2.7:
    # 3 Tx-Ports (4-Phases)
    Common_vars.flows_per_port = 'single'
    # Phase 2:
    flow_configs = {'test_case': '2.7 phase 2',
                    'total_tx_ports': 3,
                    'weight_distribution_type': 'sequential',
                    'tx_port_flows': [{'queue_id': 1, 'weight': 20, 'line_rate': 40,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 20},
                                      {'queue_id': 2, 'weight': 50, 'line_rate': 60,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 50},
                                      {'queue_id': 3, 'weight': 30, 'line_rate': 40,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 30}]}

    # Avoid egress tracking for test case 2.6 because of flow name getting reset and need to be renamed
    control_state_obj = execute_common_configs(duthosts, create_snappi_config, snappi_api,
                                               get_snappi_ports, subnet_type,
                                               flow_configs, config_egress_tracking=True,
                                               enable_pkt_sequence_checking=False)
    verify_line_rate(Common_vars, duthosts, snappi_api, control_state_obj)
    stop_traffic(snappi_api, control_state_obj)
    delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)


@pytest.mark.parametrize("subnet_type", ["IPv4"])
def test_dwrr_wred_with_extreme_weight_ratio_7_phase_3(snappi_api,                 # noqa F811
                                                       conn_graph_facts,           # noqa F811
                                                       fanout_graph_facts_multidut, # noqa F811
                                                       duthosts,
                                                       set_primary_chassis, # noqa F811
                                                       rand_one_dut_hostname,
                                                       rand_one_dut_portname_oper_up,
                                                       get_snappi_ports, # noqa F811
                                                       subnet_type, # noqa F811
                                                       create_snappi_config, # noqa F811
                                                       local_script_setup_and_teardown
                                                       ):
    Common_vars.subnet_type = subnet_type

    # TC 2.7:
    # Phase 3
    flow_configs = {'test_case': '2.7 phase 3',
                    'total_tx_ports': 3,
                    'weight_distribution_type': 'sequential',
                    'tx_port_flows': [{'queue_id': 1, 'weight': 20, 'line_rate': 50,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 20},
                                      {'queue_id': 2, 'weight': 50, 'line_rate': 50,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 50},
                                      {'queue_id': 3, 'weight': 30, 'line_rate': 50,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 30}]}

    # Avoid egress tracking for test case 2.6 because of flow name getting reset and need to be renamed
    control_state_obj = execute_common_configs(duthosts, create_snappi_config,
                                               snappi_api, get_snappi_ports,
                                               subnet_type, flow_configs,
                                               config_egress_tracking=True,
                                               enable_pkt_sequence_checking=False)
    verify_line_rate(Common_vars, duthosts, snappi_api, control_state_obj)
    stop_traffic(snappi_api, control_state_obj)
    delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)


@pytest.mark.parametrize("subnet_type", ["IPv4"])
def test_dwrr_wred_with_extreme_weight_ratio_7_phase_4(snappi_api,                 # noqa F811
                                                       conn_graph_facts,           # noqa F811
                                                       fanout_graph_facts_multidut, # noqa F811
                                                       duthosts,
                                                       set_primary_chassis, # noqa F811
                                                       rand_one_dut_hostname,
                                                       rand_one_dut_portname_oper_up,
                                                       get_snappi_ports, # noqa F811
                                                       subnet_type, # noqa F811
                                                       create_snappi_config, # noqa F811
                                                       local_script_setup_and_teardown
                                                       ):
    Common_vars.subnet_type = subnet_type

    # TC 2.7:
    # 3 Tx-Ports (4-Phases)
    Common_vars.flows_per_port = 'single'
    flow_configs = {'test_case': '2.7 phase 4',
                    'total_tx_ports': 3,
                    'weight_distribution_type': 'sequential',
                    'tx_port_flows': [{'queue_id': 1, 'weight': 20, 'line_rate': 70,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 20},
                                      {'queue_id': 2, 'weight': 50, 'line_rate': 70,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 50},
                                      {'queue_id': 3, 'weight': 30, 'line_rate': 60,
                                       'frame_size': Common_vars.frame_size,
                                       'expected_line_rate': 30}]}

    # Avoid egress tracking for test case 2.6 because of flow name getting reset and need to be renamed
    control_state_obj = execute_common_configs(duthosts, create_snappi_config, snappi_api,
                                               get_snappi_ports, subnet_type,
                                               flow_configs, config_egress_tracking=True,
                                               enable_pkt_sequence_checking=False)
    verify_line_rate(Common_vars, duthosts, snappi_api, control_state_obj)
    stop_traffic(snappi_api, control_state_obj)
    delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)


@pytest.mark.parametrize("subnet_type", ["IPv4"])
def test_dwrr_wred_with_extreme_weight_ratio_8(snappi_api,                 # noqa F811
                                               conn_graph_facts,           # noqa F811
                                               fanout_graph_facts_multidut, # noqa F811
                                               duthosts,
                                               set_primary_chassis, # noqa F811
                                               rand_one_dut_hostname,
                                               rand_one_dut_portname_oper_up,
                                               get_snappi_ports, # noqa F811
                                               subnet_type,
                                               create_snappi_config, # noqa F811
                                               local_script_setup_and_teardown
                                               ):
    """
    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        setup_snappi_port_configs (pytest fixture): Returns a list of dicts
                    containing all snappi port srcIp, gateways, duthost, etc
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g.,
                    's6100-1|Ethernet0'

    Returns:
        N/A
    """
    # TC 2.8 :
    # Packet sequence checking
    Common_vars.flows_per_port = 'single'
    Common_vars.pass_threshold_pct = .05
    flow_configs = {'test_case': '2.8',
                    'total_tx_ports': 4,
                    'weight_distribution_type': 'sequential',
                    'tx_port_flows': [{'queue_id': 1,
                                       'weight': 25,
                                       'line_rate': 24,
                                       'frame_size': [64, 1, 512, 1, 1024, 1, 1500, 1],
                                       'expected_line_rate': 24},
                                      {'queue_id': 2,
                                       'weight': 25,
                                       'line_rate': 24,
                                       'frame_size': [64, 1, 512, 1, 1024, 1, 1500, 1],
                                       'expected_line_rate': 24},
                                      {'queue_id': 3,
                                       'weight': 25,
                                       'line_rate': 24,
                                       'frame_size': [64, 1, 512, 1, 1024, 1, 1500, 1],
                                       'expected_line_rate': 24},
                                      {'queue_id': 4,
                                       'weight': 25,
                                       'line_rate': 25,
                                       'frame_size': [64, 1, 512, 1, 1024, 1, 1500, 1],
                                       'expected_line_rate': 25}]}

    Common_vars.subnet_type = subnet_type
    control_state_obj = execute_common_configs(duthosts, create_snappi_config,
                                               snappi_api, get_snappi_ports,
                                               subnet_type, flow_configs,
                                               config_egress_tracking=True,
                                               enable_pkt_sequence_checking=True)
    verify_line_rate(Common_vars, duthosts, snappi_api, control_state_obj)
    stop_traffic(snappi_api, control_state_obj)
    verify_frames(Common_vars, duthosts, snappi_api, control_state_obj,
                  pkt_sequence_checking_enabled=True)
    delete_flows(Common_vars, snappi_api, remove_egress_stat_view=True)
