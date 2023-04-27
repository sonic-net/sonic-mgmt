from tests.common.snappi.snappi_fixtures import (                           # noqa F401
    cvg_api, snappi_api_serv_ip, snappi_api_serv_port, tgen_ports)
from .files.bgp_test_gap_helper import run_bgp_convergence_performance
from tests.common.fixtures.conn_graph_facts import (                        # noqa F401
    conn_graph_facts, fanout_graph_facts)
import pytest

pytestmark = [pytest.mark.topology('tgen')]


@pytest.mark.parametrize('multipath', [2])
@pytest.mark.parametrize('start_routes', [500])
@pytest.mark.parametrize('routes_step', [500])
@pytest.mark.parametrize('stop_routes', [16000])
@pytest.mark.parametrize('route_type', ['IPv4'])
def test_bgp_convergence_performance(cvg_api,               # noqa F811
                                     duthost,
                                     tgen_ports,            # noqa F811
                                     multipath,
                                     start_routes,
                                     routes_step,
                                     stop_routes,
                                     route_type,):
    """
    Topo:
    TGEN1 --- DUT --- TGEN(2..N)

    Steps:
    1) Create BGP config on DUT and TGEN respectively
    2) Create a flow from TGEN1 to (N-1) TGEN ports
    3) Send Traffic from TGEN1 to (N-1) TGEN ports having the same route range
    4) Simulate route withdraw from one of the (N-1) BGP peers
    5) Calculate the convergence time for routes
    6) Clean up the BGP config on the dut

    Verification:
    1) Send traffic with all routes advertised by BGP peers
        Result: Should not observe traffic loss
    2) Withdraw all routes from one of the BGP peer
        Result: Traffic must be routed via rest of the ECMP paths without loss

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        multipath: ECMP value
        start_routes: starting value of no of routes
        routes_step: incremental step value for the routes
        stop_routes: ending route count value
        route_type: IPv4 or IPv6 routes
    """
    run_bgp_convergence_performance(cvg_api,
                                    duthost,
                                    tgen_ports,
                                    multipath,
                                    start_routes,
                                    routes_step,
                                    stop_routes,
                                    route_type,)
