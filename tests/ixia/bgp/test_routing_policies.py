import pytest
import logging
from tests.common.ixia.ixia_fixtures import snappi_api
from tests.common.ixia.ixia_fixtures import (
    ixia_api_serv_ip, ixia_api_serv_port, tgen_ports)
from files.helper import (
    run_peer_routing_policies_test, run_community_list_filtering_test,
    run_prefix_list_filtering_test, run_test_metric_filter,
    run_group_as_path_modified, run_origin_code_modification,
    config_setup, config_cleanup)
from tests.common.fixtures.conn_graph_facts import (
    conn_graph_facts, fanout_graph_facts)
logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def setup_and_teardown(duthost,
                       tgen_ports):
    """
    Setup and Teardown
    """
    # We are going to use first two ports for all these tests
    tgen_ports = tgen_ports[0:2]
    logger.info("|--Common Setup Configuration--|")
    config_setup(duthost,
                 tgen_ports)
    yield
    logger.info("|--Common Cleanup--|")
    config_cleanup(duthost,
                   tgen_ports)


# Test 1
@pytest.mark.topology("tgen")
def test_peer_routing_policies(snappi_api,
                               duthost,
                               tgen_ports,
                               conn_graph_facts,
                               fanout_graph_facts,
                               setup_and_teardown):
    """
    Topo:
    TGEN1 --- DUT --- TGEN2

    Steps:
    1) Create BGP config on DUT and TGEN respectively
    2) Generate 2 ipv4 routes & 2 ipv6 routes from TGEN1
       -- "200.1.0.0" & "4000::1" with Attributes
            a) community-list 1:2
            b) as-path append AS 100
            c) Origin ebgp
            d) Metric 50
       -- "20.1.0.0" & "6000::1"
    3) Create route-map in DUT to permit only "200.1.0.0"
       & "4000::1" based on BGP Attributes
    4) Create four flows from TGEN2 to TGEN1
        a) 'permit' -- TGEN2 to TGEN1("200.1.0.0")
        b) 'permit_ipv6' -- TGEN2 to TGEN1("4000::1")
        c) 'deny'   -- TGEN2 to TGEN1("20.1.0.0")
        d) 'deny_ipv6' -- TGEN2 to TGEN1("6000::1")

    Verification:
    1) Send traffic without applying route-map
        Result: Should not observe traffic loss in 'permit' & 'deny'
                'permit_ipv6' & 'deny_ipv6'
    2) Apply route-map
        Result: Should observe 100% traffic loss in 'deny' & 'deny_ipv6'

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
    """

    tgen_ports = tgen_ports[0:2]
    logger.info("|--BGP Peer Policies Test--|")
    run_peer_routing_policies_test(snappi_api,
                                   duthost,
                                   tgen_ports)


# Test 2
@pytest.mark.topology("tgen")
def test_community_list_filtering(snappi_api,
                                  duthost,
                                  tgen_ports,
                                  conn_graph_facts,
                                  fanout_graph_facts,
                                  setup_and_teardown):
    """
    Topo:
    TGEN1 --- DUT --- TGEN2

    Steps:
    1) Create BGP config on DUT and TGEN respectively
    2) Generate 2 ipv4 routes & 2 ipv6 routes from TGEN1
       -- "200.1.0.0" & "4000::1" with Community Attribute 1:2
       -- "20.1.0.0" & "6000::1"
    3) Create route-map in DUT to permit only "200.1.0.0"
       & "4000::1" based on Community Attribute
    4) Create four flows from TGEN2 to TGEN1
        a) 'permit' -- TGEN2 to TGEN1("200.1.0.0")
        b) 'permit_ipv6' -- TGEN2 to TGEN1("4000::1")
        c) 'deny'   -- TGEN2 to TGEN1("20.1.0.0")
        d) 'deny_ipv6' -- TGEN2 to TGEN1("6000::1")

    Verification:
    1) Send traffic without applying route-map
        Result: Should not observe traffic loss in 'permit' & 'deny'
                'permit_ipv6' & 'deny_ipv6'
    2) Apply route-map
        Result: Should observe 100% traffic loss in 'deny' & 'deny_ipv6'

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
    """

    tgen_ports = tgen_ports[0:2]
    logger.info("|--BGP Community List Filtering Test--|")
    run_community_list_filtering_test(snappi_api,
                                      duthost,
                                      tgen_ports)


# Test 3
@pytest.mark.topology("tgen")
def test_prefix_list_filtering(snappi_api,
                               duthost,
                               tgen_ports,
                               conn_graph_facts,
                               fanout_graph_facts,
                               setup_and_teardown):
    """
    Topo:
    TGEN1 --- DUT --- TGEN2

    Steps:
    1) Create BGP config on DUT and TGEN respectively
    2) Generate 2 ipv4 routes & 2 ipv6 routes from TGEN1
       -- "200.1.0.0" & "4000::1"
       -- "20.1.0.0" & "6000::1"
    3) Create Prefix-list route-map in DUT to permit
       only "200.1.0.0" & "4000::1"
    4) Create four flows from TGEN2 to TGEN1
        a) 'permit' -- TGEN2 to TGEN1("200.1.0.0")
        b) 'permit_ipv6' -- TGEN2 to TGEN1("4000::1")
        c) 'deny'   -- TGEN2 to TGEN1("20.1.0.0")
        d) 'deny_ipv6' -- TGEN2 to TGEN1("6000::1")

    Verification:
    1) Send traffic without applying route-map
        Result: Should not observe traffic loss in 'permit' & 'deny'
                'permit_ipv6' & 'deny_ipv6'
    2) Apply route-map
        Result: Should observe 100% traffic loss in 'deny' & 'deny_ipv6'

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
    """

    tgen_ports = tgen_ports[0:2]
    logger.info("|--BGP Prefix List Filtering Test--|")
    run_prefix_list_filtering_test(snappi_api,
                                   duthost,
                                   tgen_ports)


# Test 4
@pytest.mark.topology("tgen")
def test_metric_filter(snappi_api,
                       duthost,
                       tgen_ports,
                       conn_graph_facts,
                       fanout_graph_facts,
                       setup_and_teardown):
    """
    Topo:
    TGEN1 --- DUT --- TGEN2

    Steps:
    1) Create BGP config on DUT and TGEN respectively
    2) Generate 2 ipv4 routes & 2 ipv6 routes from TGEN1
       -- "200.1.0.0" & "4000::1" with Metric 50
       -- "20.1.0.0" & "6000::1"
    3) Create route-map in DUT to permit only "200.1.0.0"
       & "4000::1" based on Metric
    4) Create four flows from TGEN2 to TGEN1
        a) 'permit' -- TGEN2 to TGEN1("200.1.0.0")
        b) 'permit_ipv6' -- TGEN2 to TGEN1("4000::1")
        c) 'deny'   -- TGEN2 to TGEN1("20.1.0.0")
        d) 'deny_ipv6' -- TGEN2 to TGEN1("6000::1")

    Verification:
    1) Send traffic without applying route-map
        Result: Should not observe traffic loss in 'permit' & 'deny'
                'permit_ipv6' & 'deny_ipv6'
    2) Apply route-map
        Result: Should observe 100% traffic loss in 'deny' & 'deny_ipv6'

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
    """

    tgen_ports = tgen_ports[0:2]
    logger.info("|--BGP Metric Filter Test--|")
    run_test_metric_filter(snappi_api,
                           duthost,
                           tgen_ports)


# Test 5
@pytest.mark.topology("tgen")
def test_group_as_path_modified(snappi_api,
                                duthost,
                                tgen_ports,
                                conn_graph_facts,
                                fanout_graph_facts,
                                setup_and_teardown):
    """
    Topo:
    TGEN1 --- DUT --- TGEN2

    Steps:
    1) Create BGP config on DUT and TGEN respectively
    2) Generate 2 ipv4 routes & 2 ipv6 routes from TGEN1
       -- "200.1.0.0" & "4000::1" with group AS
       -- "20.1.0.0" & "6000::1"
    3) Create route-map in DUT to permit only "200.1.0.0"
       & "4000::1" based on group AS
    4) Create four flows from TGEN2 to TGEN1
        a) 'permit' -- TGEN2 to TGEN1("200.1.0.0")
        b) 'permit_ipv6' -- TGEN2 to TGEN1("4000::1")
        c) 'deny'   -- TGEN2 to TGEN1("20.1.0.0")
        d) 'deny_ipv6' -- TGEN2 to TGEN1("6000::1")

    Verification:
    1) Send traffic without applying route-map
        Result: Should not observe traffic loss in 'permit' & 'deny'
                'permit_ipv6' & 'deny_ipv6'
    2) Apply route-map
        Result: Should observe 100% traffic loss in 'deny' & 'deny_ipv6'

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
    """

    tgen_ports = tgen_ports[0:2]
    logger.info("|--BGP group-as-path modified Test--|")
    run_group_as_path_modified(snappi_api,
                               duthost,
                               tgen_ports)


# Test 6
@pytest.mark.topology("tgen")
def test_origin_code_modification(snappi_api,
                                  duthost,
                                  tgen_ports,
                                  conn_graph_facts,
                                  fanout_graph_facts,
                                  setup_and_teardown):
    """
    Topo:
    TGEN1 --- DUT --- TGEN2

    Steps:
    1) Create BGP config on DUT and TGEN respectively
    2) Generate 2 ipv4 routes & 2 ipv6 routes from TGEN1
       -- "200.1.0.0" & "4000::1" with Origin 'egp'
       -- "20.1.0.0" & "6000::1"
    3) Create route-map in DUT to permit only "200.1.0.0"
       & "4000::1" based on Origin 'egp'
    4) Create four flows from TGEN2 to TGEN1
        a) 'permit' -- TGEN2 to TGEN1("200.1.0.0")
        b) 'permit_ipv6' -- TGEN2 to TGEN1("4000::1")
        c) 'deny'   -- TGEN2 to TGEN1("20.1.0.0")
        d) 'deny_ipv6' -- TGEN2 to TGEN1("6000::1")

    Verification:
    1) Send traffic without applying route-map
        Result: Should not observe traffic loss in 'permit' & 'deny'
                'permit_ipv6' & 'deny_ipv6'
    2) Apply route-map
        Result: Should observe 100% traffic loss in 'deny' & 'deny_ipv6'

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
    """

    tgen_ports = tgen_ports[0:2]
    logger.info("|--BGP Group-Origin Code Modifcation Test--|")
    run_origin_code_modification(snappi_api,
                                 duthost,
                                 tgen_ports)