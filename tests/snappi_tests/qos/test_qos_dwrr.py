"""
This script performs two types of tests:
   1> Inter-port testing
   2> Intra-port testing

- Every port is tested as a Rx-Port
- This script reads the DUT configs for interface queue scheduler ID mapping to its weights, and
  uses the weight to determine the expected bandwidth for the flow, and verify the traffic pass criteria based on that.
"""

import logging
import pytest
from time import sleep
# from rich import print as pr

from tests.snappi_tests.qos.files.qos_priority_helper import initiate_snappi_port_groups_dict, \
    define_tx_rx_inter_port_testing, define_tx_rx_intra_port_testing, verify_dut_ports_up, \
    read_dut_configs, create_snappi_flows_dwrr, run_traffic,  delete_flows, stop_traffic, \
    map_scheduler_id_by_weight, verify_dwrr_pass_criteria
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts, fanout_graph_facts_multidut # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     snappi_api,  get_snappi_ports, get_snappi_ports_single_dut, get_snappi_ports_multi_dut, \
     snappi_testbed_config     # noqa F401

from tests.snappi_tests.dataplane.files.helper import get_duthost_interface_details
from tests.snappi_tests.dataplane.files.helper import set_primary_chassis  # noqa F401 
from tests.snappi_tests.dataplane.files.helper import create_snappi_config, create_snappi_config  # noqa F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.snappi_helpers import wait_for_arp

logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('tgen')]


class Common_vars:
    # Allowed user defined settings
    frame_size = 1500
    line_rate_percentage = 100
    flow_duration_seconds = 60
    pass_threshold_pct = 0.02

    # Do you want to test every 100G port within the 800G physical port as rx-port?
    # Set the total number of rx-ports to test.
    # 8x100G ports per per group.
    # 1=(Mainly for a quick test) testing just one port in the port-group as rx-port
    # 8=testing all 8 ports in the port-group as rx-port
    total_rx_port_rotation = 1

    # --- DON'T TOUCH BELOW VALUES ---

    # Options: dwrr | dwrr+wred
    type_of_test = 'dwrr'
    # Leave values as default. Values are based on 800G physical port.
    # Breaking down ports to 8-100G ports. 1 port for rx-port. 7 ports for tx-ports.
    ports_per_group = 8
    total_tx_ports_per_physical_port = 7

    # For verify_dut_ports_up()
    tx_port_names_for_verify_port_up = ''
    traffic_flows = []
    # The amount of endpoints per flow: single | multiple.  TC 2.6 uses multiple
    flows_per_port = 'single'
    snappi_port_groups = {}
    snappi_configs = None
    dut_qos_configs = {}
    # Use the weight to get the scheduleId for Ethernet interface queue IDs
    scheduler_to_weight_dict = {}
    weight_to_scheduler_dict = {}
    # {'sonic-s6100-dut1': [1, 3]}
    port_group_range = {}
    # {'sonic-s6100-dut1': {1: {'rx_ports': [], 'tx_ports': [], 'queue_id_list': [],
    # 'dscp_tos_generator': {}, 'flows': []}, 3:
    # {'rx_ports': [], 'tx_ports': [], 'queue_id_list': [], 'dscp_tos_generator': {},
    # 'flows': []}}}
    snappi_port_groups = {}
    # Get the queue ID's weight for verify passed/failed traffic
    get_queue_id_weight = {}
    flow_configs = {}
    # Avoid keep reading/rebooting the DUT config and defining port settings on every test case.
    # Just do it once
    initiated_port_configs = False
    # IPv4 | IPv6
    subnet_type = 'IPv4'


def execute_common_configs(rx_port_index,
                           duthosts,
                           create_snappi_config, # noqa F811
                           snappi_api, # noqa F811
                           snappi_extra_params,
                           snappi_ports):
    if Common_vars.initiated_port_configs is False:
        Common_vars.initiated_port_configs = True

        for duthost in duthosts:
            Common_vars.scheduler_to_weight_dict, Common_vars.weight_to_scheduler_dict = \
                map_scheduler_id_by_weight(duthost)

        for duthost in duthosts:
            verify_dut_ports_up(duthost, Common_vars.tx_port_names_for_verify_port_up)

        read_dut_configs(Common_vars, duthosts)

        # Add ports and configure IP interfaces on traffic generator
        Common_vars.snappi_configs, snappi_obj_handles = create_snappi_config(snappi_extra_params)
        # Execute config ports and NGPF configs
        snappi_api.set_config(Common_vars.snappi_configs)

        logger.info('Wait for Arp to Resolve ...')
        if wait_for_arp(snappi_api, max_attempts=10, poll_interval_sec=2) != 0:
            pytest_assert(False, "ARP failed")
    else:
        read_dut_configs(Common_vars, duthosts)

    create_snappi_flows_dwrr(Common_vars, duthosts, snappi_api, snappi_ports)
    
    control_state_obj = run_traffic(Common_vars, duthosts, snappi_api=snappi_api,
                                    config=Common_vars.snappi_configs)
    sleep(Common_vars.flow_duration_seconds)
    verify_dwrr_pass_criteria(Common_vars, snappi_api, control_state_obj)
    stop_traffic(snappi_api, control_state_obj)
    delete_flows(Common_vars, snappi_api, remove_egress_stat_view=False)


@pytest.mark.parametrize("subnet_type", ["IPv4"])
def test_qos_dwrr_intra_port(snappi_api,                 # noqa F811
                             conn_graph_facts,           # noqa F811
                             fanout_graph_facts_multidut, # noqa F811
                             duthosts,
                             set_primary_chassis, # noqa F811
                             rand_one_dut_hostname,
                             rand_one_dut_portname_oper_up,
                             get_snappi_ports, # noqa F811
                             create_snappi_config, # noqa F811
                             subnet_type
                             ):
    """
    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        setup_snappi_port_configs (pytest fixture): Returns a list of
              dicts containing all snappi port srcIp, gateways, duthost, etc
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g.,
              's6100-1|Ethernet0'

    Returns:
        N/A
    """
    Common_vars.subnet_type = subnet_type
    snappi_extra_params = SnappiTestParams()
    snappi_ports = get_duthost_interface_details(duthosts, get_snappi_ports,
                                                 subnet_type, protocol_type='ip')

    tx_ports = [snappi_ports[0]]
    rx_ports = snappi_ports[1:]

    snappi_extra_params.protocol_config = {
        "Tx": {"protocol_type": "ip", "is_rdma": True,
               "ports": tx_ports, "subnet_type": subnet_type},
        "Rx": {"protocol_type": "ip", "is_rdma": True,
               "ports": rx_ports, "subnet_type": subnet_type},
    }

    # Test all 64 ports in one single DUT
    # In groups of 8 ports, rotate each port to be a rx-port so every port is QoS-tested as a rx-port
    for rx_port_index in range(Common_vars.total_rx_port_rotation):
        initiate_snappi_port_groups_dict(Common_vars, duthosts, snappi_ports)
        define_tx_rx_intra_port_testing(Common_vars, snappi_ports, rx_port_index)
        execute_common_configs(rx_port_index, duthosts, create_snappi_config,
                               snappi_api, snappi_extra_params, snappi_ports)


@pytest.mark.parametrize("subnet_type", ["IPv4"])
def test_qos_dwrr_inter_port(snappi_api,                           # noqa F811
                             conn_graph_facts,             # noqa F811
                             fanout_graph_facts_multidut, # noqa F811
                             duthosts,
                             set_primary_chassis, # noqa F811
                             rand_one_dut_hostname,
                             rand_one_dut_portname_oper_up,
                             get_snappi_ports, # noqa F811
                             create_snappi_config, # noqa F811
                             subnet_type # noqa F811
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
    Common_vars.subnet_type = subnet_type
    snappi_extra_params = SnappiTestParams()
    snappi_ports = get_duthost_interface_details(duthosts, get_snappi_ports,
                                                 subnet_type, protocol_type='ip')
    tx_ports = [snappi_ports[0]]
    rx_ports = snappi_ports[1:]

    snappi_extra_params.protocol_config = {
        "Tx": {"protocol_type": "ip", "is_rdma": True, "ports": tx_ports, "subnet_type": subnet_type},
        "Rx": {"protocol_type": "ip", "is_rdma": True, "ports": rx_ports, "subnet_type": subnet_type},
    }

    for rx_port_index in range(Common_vars.total_rx_port_rotation):
        initiate_snappi_port_groups_dict(Common_vars, duthosts, snappi_ports)
        define_tx_rx_inter_port_testing(Common_vars, snappi_ports, rx_port_index)
        execute_common_configs(rx_port_index, duthosts, create_snappi_config,
                               snappi_api, snappi_extra_params, snappi_ports)




