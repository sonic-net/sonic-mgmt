import pytest
import logging

from tests.common.helpers.assertions import pytest_require    # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts, fanout_graph_facts_multidut # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_snappi_ports_for_rdma, cleanup_config, get_snappi_ports_multi_dut, \
    snappi_testbed_config, get_snappi_ports_single_dut, \
    get_snappi_ports, is_snappi_multidut # noqa F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, \
    lossless_prio_list   # noqa F401
from tests.snappi_tests.multidut.pfc.files.multidut_helper import run_tx_drop_counter
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.snappi_tests.files.helper import multidut_port_info, setup_ports_and_dut  # noqa: F401

logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


@pytest.fixture(autouse=True)
def number_of_tx_rx_ports():
    yield (1, 1)


def test_tx_drop_counter(
                    snappi_api, # noqa F811
                    lossless_prio_list, # noqa F811
                    prio_dscp_map,# noqa F811
                    setup_ports_and_dut # noqa F811
                    ):
    """
    Test if device under test (DUT) is incrementing
    the tx_drop counter of the egress port when oper down

    Topology:
    snappi (1) -> DUT -> snappi (2)

    Test steps:
    1) Bring the egress DUT port to oper down state by changing the IXIA port  to down state
    2) With lossless priority configured on the egress port the Xon frames or any control plane pkts
    previously being sent out shouldnt be sent and also it shouldn't be accounted for as tx drop counter

    Args:
        snappi_api (pytest fixture): SNAPPI session
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    testbed_config, port_config_list, snappi_ports = setup_ports_and_dut

    logger.info("Snappi Ports : {}".format(snappi_ports))

    test_prio_list = lossless_prio_list

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_tx_drop_counter(
                    api=snappi_api,
                    testbed_config=testbed_config,
                    port_config_list=port_config_list,
                    dut_port=snappi_ports[0]['peer_port'],
                    test_prio_list=test_prio_list,
                    prio_dscp_map=prio_dscp_map,
                    snappi_extra_params=snappi_extra_params
                    )
