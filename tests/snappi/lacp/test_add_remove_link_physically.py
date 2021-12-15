from tests.common.snappi.snappi_fixtures import cvg_api
from tests.common.snappi.snappi_fixtures import (
    snappi_api_serv_ip, snappi_api_serv_port, tgen_ports)
from files.lacp_physical_helper import run_lacp_add_remove_link_physically
from tests.common.fixtures.conn_graph_facts import (
    conn_graph_facts, fanout_graph_facts)
import pytest


@pytest.mark.parametrize('port_count', [4])
@pytest.mark.parametrize('number_of_routes', [1000])
@pytest.mark.parametrize('port_speed',['speed_100_gbps'])
def test_lacp_add_remove_link_physically(cvg_api,
                                        duthost,
                                        tgen_ports,
                                        conn_graph_facts,
                                        fanout_graph_facts,
                                        port_count,
                                        number_of_routes,
                                        port_speed,):

    """
    Topo:
    TGEN1 --- DUT --- TGEN(2..N)

    Steps:
    1) Create BGP config on DUT and TGEN respectively
    2) Create a flow from TGEN1 to (N-1) TGEN ports
    3) Send Traffic from TGEN1 to (N-1) TGEN ports having the same route range
    4) Simulate link failure by bringing down one of the (N-1) TGEN Ports
    5) Calculate the packet loss duration for convergence time
    6) Clean up the BGP config on the dut

    Verification:
    1) Send traffic without flapping any link
       Result: Should not observe traffic loss
    2) Flap one of the N TGEN link
        Result: The traffic must be routed via rest of the ECMP paths

    Args:
        cvg_api (pytest fixture): Snappi Convergence API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        port_count: Total no of ports used in the test
        number_of_routes:  Number of IPv4/IPv6 Routes
        port_speed: speed of the port used for test
    """
    # port_count, number_of_routes and port_speed parameters can be modified as per user preference
    run_lacp_add_remove_link_physically(cvg_api,
                                     duthost,
                                     tgen_ports,
                                     port_count,
                                     number_of_routes,
                                     port_speed,)
