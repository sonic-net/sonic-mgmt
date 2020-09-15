###############################################################################
# This test case demonstrates:
#   * All the fixtures required for running ixia script (please see the
#     arguments of the test function)
#   * How Ixia chassis card/ports are addressed
#   * How you can configure/control ixia devices, start traffic and collect
#     statistics.
#   * This simple sanity test case can be used to check if testbed setup
#     is correct or not.
###############################################################################

import logging
import time
import pytest
from tests.common.utilities import wait_until
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, \
    fanout_graph_facts

from tests.common.reboot import logger

from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_user,\
    ixia_api_serv_passwd, ixia_api_serv_port, ixia_api_serv_session_id, \
    ixia_api_server_session

from tests.common.ixia.ixia_helpers import  IxiaFanoutManager, configure_ports,\
    create_topology, create_ip_traffic_item, start_protocols, \
    start_traffic, stop_traffic, get_traffic_statistics, stop_protocols

from tests.common.ixia.common_helpers import increment_ip_address

def test_testbed(conn_graph_facts, duthost, fanout_graph_facts,
    ixia_api_server_session, fanouthosts):

    logger.info("Connection Graph Facts = %s " %(conn_graph_facts))
    logger.info("Fanout Graph facts = %s" %(fanout_graph_facts))
    logger.info("DUT hostname = %s" %(duthost.hostname))

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)
    gateway_ip = mg_facts['ansible_facts']['minigraph_vlan_interfaces'][0]['addr']
    start_interface_ip = increment_ip_address(gateway_ip)

    ixiaFanoutHostList = IxiaFanoutManager(fanout_graph_facts)
    ixiaFanoutHostList.get_fanout_device_details(device_number = 0)

    session = ixia_api_server_session

    logger.info("Configuring ports.")
    port_list = configure_ports(session=session,
                                port_list=ixiaFanoutHostList.get_ports())

    logger.info("Creating topology.")
    topology = create_topology(session=session,
                               ports=port_list,
                               name="Sender",
                               ip_start=start_interface_ip,
                               ip_incr_step='0.0.0.1',
                               gw_start=gateway_ip,
                               gw_incr_step='0.0.0.0')

    logger.info("Starting all protocols")
    start_protocols(session)

    # Create a traffic item
    logger.info("Configuring traffic.")
    traffic_item = create_ip_traffic_item(
        session=session,
        src_start_port=1,
        src_port_count=1,
        src_first_route_index=1,
        src_route_count=1,
        dst_start_port=2,
        dst_port_count=3,
        dst_first_route_index=1,
        dst_route_count=1)

    # Generate, apply and start traffic.
    start_traffic(session)

    logger.info("run traffic for 5 seconds")
    time.sleep(5)

    # Fetch statistics.
    stats = get_traffic_statistics(session=session,
        stat_view_name='Traffic Item Statistics')
    logger.info(stats)

    stop_traffic(session)
    stop_protocols(session)

