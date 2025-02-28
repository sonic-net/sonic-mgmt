import pytest
import logging
from tests.common.helpers.assertions import pytest_require, pytest_assert                            # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, \
     fanout_graph_facts_multidut                                                                    # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     cvg_api, multidut_snappi_ports_for_bgp                                                         # noqa: F401
from tests.snappi_tests.variables import t1_t2_device_hostnames                                     # noqa: F401
from tests.snappi_tests.multidut.bgp.files.bgp_performance_helper import (
     run_bgp_route_delete_test)                                                                    # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams                           # noqa: F401
from tests.snappi_tests.variables import PERFORMANCE_PORTS                                          # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]

ITERATION = 1
ROUTE_RANGES = [{
                'IPv4': [
                    ['100.1.1.1', 24, 5000],
                    ['200.1.1.1', 24, 5000]
                ]
                },
                {
                'IPv4': [
                    ['100.1.1.1', 24, 25000],
                    ['200.1.1.1', 24, 25000]
                ]
                }]


def test_bgp_route_delete(cvg_api,                                     # noqa: F811
                            duthosts,
                            conn_graph_facts,                             # noqa: F811
                            fanout_graph_facts_multidut,                   # noqa: F811
                            multidut_snappi_ports_for_bgp):                # noqa: F811
    """
    Gets the packet loss duration on flapping services in uplink

    Args:
        cvg_api (pytest fixture): Snappi convergence api
        multidut_snappi_ports_for_bgp (pytest fixture):  Port mapping info on multidut testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
    Returns:
        N/A
    """
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.ROUTE_RANGES = ROUTE_RANGES
    snappi_extra_params.test_name = 'Route delete For Multiple BGP Session'
    snappi_extra_params.iteration = ITERATION
    snappi_extra_params.multi_dut_params.multi_dut_ports = multidut_snappi_ports_for_bgp

    ansible_dut_hostnames = []
    for duthost in duthosts:
        ansible_dut_hostnames.append(duthost.hostname)

    for t2_port in (PERFORMANCE_PORTS['Uplink BGP Session'] + PERFORMANCE_PORTS['Traffic_Tx_Ports']):
        if t2_port['hostname'] not in ansible_dut_hostnames:
            logger.info('!!!!! Attention: {} not in : {} derived from ansible dut hostnames'.
                        format(t2_port['hostname'], ansible_dut_hostnames))
            pytest_assert(False, "Mismatch between the dut hostnames in ansible and in variables.py files")

    pytest_assert(len(PERFORMANCE_PORTS['Traffic_Tx_Ports']) >= 2, "Need Minimum of 2 Tx ports for this test")
    pytest_assert(len(PERFORMANCE_PORTS['Uplink BGP Session']) >= 1, "Need Minimum of 1 Rx ports for this test")
    run_bgp_route_delete_test(api=cvg_api,
                              duthosts=duthosts,
                              snappi_extra_params=snappi_extra_params)
