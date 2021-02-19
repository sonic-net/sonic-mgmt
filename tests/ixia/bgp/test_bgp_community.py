from tests.common.ixia.ixia_fixtures import api
from tests.common.ixia.ixia_fixtures import tgen_ports
from files.helper import run_bgp_community_test
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
import logging


logger = logging.getLogger(__name__)

def test_bgp_community(api,
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
    3) Create community list in DUT
        "ip community-list 10 permit 1:2"
    4) Create two flows from TGEN2 to TGEN1
        a) 'permit' -- TGEN2("100.1.0.0") to TGEN1("200.1.0.0")
        b) 'deny'   -- TGEN2("100.1.0.0") to TGEN1("20.1.0.0")

    Verification:
    1) Send traffic without applying route-map
        Result: Should not observe traffic loss in 'permit' & 'deny'
    2) Apply route-map
        Result: Should observe traffic loss in 'deny'
    """
    # We are going to use first two ports for this test
    tgen_ports = tgen_ports[0:2]

    run_bgp_community_test(api,
                           duthost,
                           tgen_ports)
