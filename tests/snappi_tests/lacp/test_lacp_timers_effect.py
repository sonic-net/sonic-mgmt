from tests.common.snappi_tests.snappi_fixtures import cvg_api         # noqa F401
from tests.common.snappi_tests.snappi_fixtures import (               # noqa F401
    snappi_api_serv_ip, snappi_api_serv_port, tgen_ports)
from tests.snappi_tests.lacp.files.lacp_physical_helper import run_lacp_timers_effect
from tests.common.fixtures.conn_graph_facts import (            # noqa F401
    conn_graph_facts, fanout_graph_facts)
import pytest

pytestmark = [pytest.mark.topology('tgen')]


@pytest.mark.parametrize('port_count', [4])
@pytest.mark.parametrize('number_of_routes', [1000])
@pytest.mark.parametrize('iterations', [1])
@pytest.mark.parametrize('port_speed', ['speed_100_gbps'])
@pytest.mark.parametrize('lacpdu_interval_period', [1])
@pytest.mark.parametrize('lacpdu_timeout', [90])
def test_lacp_timers(cvg_api,                       # noqa F811
                     duthost,
                     tgen_ports,                    # noqa F811
                     iterations,
                     conn_graph_facts,              # noqa F811
                     fanout_graph_facts,            # noqa F811
                     port_count,
                     number_of_routes,
                     port_speed,
                     lacpdu_interval_period,
                     lacpdu_timeout,):
    """
    Topo:
    LAG1 --- DUT --- LAG2 (N-1 TGEN Ports)

    Steps:
    1) Create BGP config on DUT and TGEN respectively
    2) Update the required LACP timers as required for the test
    3) Create a flow from LAG1 (TGEN1) to LAG2 ((N-1) TGEN ports)
    4) Send Traffic from LAG1 to LAG2
    5) Simulate link failure by bringing down one of the LAG2 Ports
    6) Ensure that packets are re-routed to rest of the LAG2 ports with no loss
    7) Measure the convergence time
    8) Clean up the BGP config on the dut

    Verification:
    1) Send traffic without flapping any link
       Result: Should not observe traffic loss
    2) Flap one of the LAG2 Ports
        Result: The traffic must be routed via rest of the LAG2 ports
    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        port_count: Total no of ports used in the test
        iterations: no of iterations to run the link flap test
        number_of_routes:  Number of IPv4/IPv6 Routes
        port_speed: speed of the port used for test
        lacpdu_interval_period: LACP update packet interval ( 0 - Auto, 1- Fast, 30 - Slow )
        lacpdu_timeout: LACP Timeout value (0 - Auto, 3 - Short, 90 - Long)
    """
    # port_count, number_of_routes ,iterations, port_speed, lacpdu_interval_period,
    # lacpdu_timeout parameters can be modified as per user preference
    run_lacp_timers_effect(cvg_api,
                           duthost,
                           tgen_ports,
                           iterations,
                           port_count,
                           number_of_routes,
                           port_speed,
                           lacpdu_interval_period,
                           lacpdu_timeout,)
