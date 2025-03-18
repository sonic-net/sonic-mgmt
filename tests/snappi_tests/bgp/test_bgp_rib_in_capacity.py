from tests.common.snappi_tests.snappi_fixtures import (                           # noqa F401
    cvg_api, snappi_api_serv_ip, snappi_api_serv_port, tgen_ports)
from tests.snappi_tests.bgp.files.bgp_convergence_helper import run_RIB_IN_capacity_test
from tests.common.fixtures.conn_graph_facts import (                        # noqa F401
    conn_graph_facts, fanout_graph_facts)
import pytest

pytestmark = [pytest.mark.topology('tgen')]


@pytest.mark.parametrize('multipath', [2])
@pytest.mark.parametrize('start_value', [1000])
@pytest.mark.parametrize('step_value', [1000])
@pytest.mark.parametrize('route_type', ['IPv4'])
@pytest.mark.parametrize('port_speed', ['speed_100_gbps'])
def test_RIB_IN_capacity(cvg_api,                   # noqa F811
                         duthost,
                         tgen_ports,                # noqa F811
                         conn_graph_facts,          # noqa F811
                         fanout_graph_facts,        # noqa F811
                         multipath,
                         start_value,
                         step_value,
                         route_type,
                         port_speed,):
    """
    Topo:
    TGEN1 --- DUT --- TGEN(2..N)

    Steps:
    1) Create a BGP config on DUT and TGEN respectively
    2) Create a flow from TGEN1 to TGEN2 port
    3) Send Traffic from TGEN1 to TGEN2 port route range
    4) Check if there is any loss observed
    5) Increment the routes in terms of step_value and repeat test untill loss is observed
    6) Note down the number of routes upto which no loss was observed which is the RIB-IN capacity value
    7) Clean up the BGP config on the dut
    Note:
        confihgure DUT interfaces prior to running test
    Verification:
    1) Send traffic and make sure there is no loss observed
    2) If loss is observed quit the test and note down the maximum routes upto which there was no loss

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        multipath: ECMP value
        start_value:  Start value of the number of BGP routes
        step_value: Step value of the number of BGP routes to be incremented
        route_type: IPv4 or IPv6 routes
        port_speed: speed of the port used for test
    """
    # multipath, start_value, step_value and route_type, port_speed parameters can be modified as per user preference
    run_RIB_IN_capacity_test(cvg_api,
                             duthost,
                             tgen_ports,
                             multipath,
                             start_value,
                             step_value,
                             route_type,
                             port_speed,)
