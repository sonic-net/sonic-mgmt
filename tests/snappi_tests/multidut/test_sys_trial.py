import pytest
from tests.common.helpers.assertions import pytest_require, pytest_assert                           # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts_multidut    # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, get_snappi_ports, snappi_port_selection                                             # noqa: F401

import logging
logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]


def test_linecard_variation_test(snappi_api,                   # noqa: F811
                                 conn_graph_facts,             # noqa: F811
                                 fanout_graph_facts_multidut,  # noqa: F811
                                 duthosts,
                                 get_snappi_ports,             # noqa: F811
                                 tbinfo):

    """
    Purpose of the test is to check if variables.py can be replaced.

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        tbinfo(key): element to identify testbed info name.
        get_snappi_ports(pytest fixture): returns list of ports based on linecards selected.
    Returns:
        N/A

    """

    rx_port_count = 2
    tx_port_count = 2
    tmp_snappi_port_list = get_snappi_ports
    # This can be assigned as snappi_port and used in the test.
    snappi_port_selection(tmp_snappi_port_list, rx_port_count, tx_port_count)
