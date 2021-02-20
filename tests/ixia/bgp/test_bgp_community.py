from tests.common.ixia.ixia_fixtures import snappi_api
from tests.common.ixia.ixia_fixtures import (
    ixia_api_serv_ip, ixia_api_serv_port, tgen_ports)
from files.helper import run_bgp_community_test
from tests.common.fixtures.conn_graph_facts import (
    conn_graph_facts, fanout_graph_facts)
import pytest


@pytest.mark.topology("tgen")
def test_bgp_community(snappi_api,
                       duthost,
                       tgen_ports,
                       conn_graph_facts,
                       fanout_graph_facts):
    """
    Topo:
    TGEN1 --- DUT --- TGEN2

    Steps:
    1) Create BGP config on DUT and TGEN respectively
    2) Generate two routes from TGEN1
       route1 -- "200.1.0.0" with community 1:2
       route2 -- "20.1.0.0"
    3) Create community list in DUT to permit only "200.1.0.0"
        "ip community-list 10 permit 1:2"
    4) Create two flows from TGEN2 to TGEN1
        a) 'permit' -- TGEN2 to TGEN1("200.1.0.0")
        b) 'deny'   -- TGEN2 to TGEN1("20.1.0.0")

    Verification:
    1) Send traffic without applying route-map
        Result: Should not observe traffic loss in 'permit' & 'deny'
    2) Apply route-map
        Result: Should observe 100% traffic loss in 'deny'

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
    """
    # We are going to use first two ports for this test
    tgen_ports = tgen_ports[0:2]

    run_bgp_community_test(snappi_api,
                           duthost,
                           tgen_ports)
