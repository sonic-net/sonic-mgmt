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

import time
import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts     # noqa F401
from tests.common.helpers.assertions import pytest_require
from tests.common.reboot import logger

from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_user,\
    ixia_api_serv_passwd, ixia_api_serv_port, ixia_api_serv_session_id, \
    ixia_api_server_session                                                                 # noqa F401
from tests.common.ixia.ixia_helpers import IxiaFanoutManager, configure_ports,\
    create_topology, create_ipv4_traffic, start_protocols, start_traffic, \
    stop_traffic, stop_protocols, dump_flow_statistics
from tests.common.ixia.common_helpers import get_vlan_subnet, get_addrs_in_subnet,\
    get_peer_ixia_chassis


pytestmark = [
    pytest.mark.topology('tgen'),
    pytest.mark.disable_loganalyzer
]


def test_testbed(conn_graph_facts, duthosts, rand_one_dut_hostname, fanout_graph_facts,     # noqa F811
                 ixia_api_server_session, fanouthosts):                                     # noqa F811
    duthost = duthosts[rand_one_dut_hostname]

    logger.info("Connection Graph Facts = %s " % (conn_graph_facts))
    logger.info("Fanout Graph facts = %s" % (fanout_graph_facts))
    logger.info("DUT hostname = %s" % (duthost.hostname))

    ixia_fanout = get_peer_ixia_chassis(conn_data=conn_graph_facts,
                                        dut_hostname=duthost.hostname)

    pytest_require(ixia_fanout is not None,
                   skip_message="Cannot find the peer IXIA chassis")

    ixia_fanout_id = list(fanout_graph_facts.keys()).index(ixia_fanout)
    ixia_fanout_list = IxiaFanoutManager(fanout_graph_facts)
    ixia_fanout_list.get_fanout_device_details(device_number=ixia_fanout_id)

    logger.info("Configuring ports.")
    port_list = ixia_fanout_list.get_ports(peer_device=duthost.hostname)
    session = ixia_api_server_session
    vports = configure_ports(session=session, port_list=port_list)

    subnet = get_vlan_subnet(duthost)
    gw = subnet.split('/')[0]
    ip_list = get_addrs_in_subnet(subnet=subnet, number_of_ip=len(vports))

    logger.info("Creating topology.")
    topo_receiver = create_topology(session=session,
                                    name="Receiver",
                                    port_list=[vports[0]],
                                    ip_list=[ip_list[0]],
                                    gw_list=[gw])

    topo_sender = create_topology(session=session,
                                  name="Sender",
                                  port_list=vports[1:],
                                  ip_list=ip_list[1:],
                                  gw_list=[gw] * len(vports[1:]))

    logger.info("Starting all protocols")
    start_protocols(session)

    # Create a traffic item
    logger.info("Configuring traffic.")
    traffic_item = create_ipv4_traffic(         # noqa F841
        session=session,
        name="Test Data Traffic",
        source=topo_sender,
        destination=topo_receiver)

    # Generate, apply and start traffic.
    start_traffic(session)

    logger.info("run traffic for 5 seconds")
    time.sleep(5)

    # Fetch per-flow statistics.
    stats = dump_flow_statistics(session=session)

    logger.info(stats)

    stop_traffic(session)
    stop_protocols(session)
