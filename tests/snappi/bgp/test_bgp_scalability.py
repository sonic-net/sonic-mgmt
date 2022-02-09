from tests.common.snappi.snappi_fixtures import cvg_api
from tests.common.snappi.snappi_fixtures import (
    snappi_api_serv_ip, snappi_api_serv_port, tgen_ports)
from files.bgp_test_gap_helper import ( 
    run_bgp_scalability_16k_v4_routes, run_bgp_scalability_8k_v6_routes, run_bgp_scalability_256_v6_routes, run_bgp_scalability_8kv4_4kv6_routes, run_bgp_scalability_100kv4_25kv6_routes)
from tests.common.fixtures.conn_graph_facts import (
    conn_graph_facts, fanout_graph_facts)
import pytest


@pytest.mark.parametrize('multipath',[1])
@pytest.mark.parametrize('ipv4_routes',[16000])
def test_bgp_scalability_16k_v4_routes(cvg_api, duthost, localhost, tgen_ports, conn_graph_facts, fanout_graph_facts, multipath, ipv4_routes):
    run_bgp_scalability_16k_v4_routes(cvg_api, duthost, localhost, tgen_ports, multipath, ipv4_routes)

@pytest.mark.parametrize('multipath',[1])
@pytest.mark.parametrize('ipv6_routes',[8000])
@pytest.mark.parametrize('ipv6_prefix',[64])
def test_bgp_scalability_8k_v6_routes(cvg_api, duthost, localhost, tgen_ports, conn_graph_facts, fanout_graph_facts, multipath, ipv6_routes, ipv6_prefix):
    run_bgp_scalability_8k_v6_routes(cvg_api, duthost, localhost, tgen_ports, multipath, ipv6_routes, ipv6_prefix)

@pytest.mark.parametrize('multipath',[1])
@pytest.mark.parametrize('ipv6_routes',[256])
@pytest.mark.parametrize('ipv6_prefix',[128])
def test_bgp_scalability_256_v6_routes(cvg_api, duthost, localhost, tgen_ports, conn_graph_facts, fanout_graph_facts, multipath, ipv6_routes, ipv6_prefix):
    run_bgp_scalability_256_v6_routes(cvg_api, duthost, localhost, tgen_ports, multipath, ipv6_routes, ipv6_prefix)

@pytest.mark.parametrize('multipath',[1])
@pytest.mark.parametrize('ipv4_routes',[8000])
@pytest.mark.parametrize('ipv6_routes',[4000])
def test_bgp_scalability_8kv4_4kv6_routes(cvg_api, duthost, localhost, tgen_ports, conn_graph_facts, fanout_graph_facts, multipath, ipv4_routes, ipv6_routes):
    run_bgp_scalability_8kv4_4kv6_routes(cvg_api, duthost, localhost, tgen_ports, multipath, ipv4_routes, ipv6_routes)

@pytest.mark.parametrize('multipath',[1])
@pytest.mark.parametrize('ipv4_routes',[100000])
@pytest.mark.parametrize('ipv6_routes',[25000])
def test_bgp_scalability_100kv4_25kv6_routes(cvg_api, duthost, localhost, tgen_ports, conn_graph_facts, fanout_graph_facts, multipath, ipv4_routes, ipv6_routes):
    run_bgp_scalability_100kv4_25kv6_routes(cvg_api, duthost, localhost, tgen_ports, multipath, ipv4_routes, ipv6_routes)
