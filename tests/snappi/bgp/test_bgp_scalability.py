from tests.common.snappi.snappi_fixtures import (                           # noqa F401
    cvg_api, snappi_api_serv_ip, snappi_api_serv_port, tgen_ports)
from .files.bgp_test_gap_helper import duthost_bgp_scalability_config, run_bgp_scalability_v4_v6, cleanup_config
from tests.common.fixtures.conn_graph_facts import (                        # noqa F401
    conn_graph_facts, fanout_graph_facts)
import pytest

pytestmark = [pytest.mark.topology('tgen')]


@pytest.mark.parametrize('multipath', [1])
def test_duthost_bgp_scalability_config(duthost, tgen_ports, multipath):        # noqa F811
    duthost_bgp_scalability_config(duthost, tgen_ports, multipath)


@pytest.mark.parametrize('multipath', [1])
@pytest.mark.parametrize('ipv4_routes', [16000])
@pytest.mark.parametrize('ipv6_routes', [1])
@pytest.mark.parametrize('ipv6_prefix', [64])
def test_bgp_scalability_16k_v4_routes(cvg_api,             # noqa F811
                                       duthost,
                                       localhost,
                                       tgen_ports,          # noqa F811
                                       multipath,
                                       ipv4_routes,
                                       ipv6_routes,
                                       ipv6_prefix):

    run_bgp_scalability_v4_v6(cvg_api,
                              duthost,
                              localhost,
                              tgen_ports,
                              multipath,
                              ipv4_routes,
                              ipv6_routes,
                              ipv6_prefix)


@pytest.mark.parametrize('multipath', [1])
@pytest.mark.parametrize('ipv4_routes', [1])
@pytest.mark.parametrize('ipv6_routes', [8000])
@pytest.mark.parametrize('ipv6_prefix', [64])
def test_bgp_scalability_8k_v6_routes(cvg_api,              # noqa F811
                                      duthost,
                                      localhost,
                                      tgen_ports,           # noqa F811
                                      multipath,
                                      ipv4_routes,
                                      ipv6_routes,
                                      ipv6_prefix):

    run_bgp_scalability_v4_v6(cvg_api,
                              duthost,
                              localhost,
                              tgen_ports,
                              multipath,
                              ipv4_routes,
                              ipv6_routes,
                              ipv6_prefix)


@pytest.mark.parametrize('multipath', [1])
@pytest.mark.parametrize('ipv4_routes', [1])
@pytest.mark.parametrize('ipv6_routes', [256])
@pytest.mark.parametrize('ipv6_prefix', [128])
def test_bgp_scalability_256_v6_routes(cvg_api,             # noqa F811
                                       duthost,
                                       localhost,
                                       tgen_ports,          # noqa F811
                                       multipath,
                                       ipv4_routes,
                                       ipv6_routes,
                                       ipv6_prefix):

    run_bgp_scalability_v4_v6(cvg_api,
                              duthost,
                              localhost,
                              tgen_ports,
                              multipath,
                              ipv4_routes,
                              ipv6_routes,
                              ipv6_prefix)


@pytest.mark.parametrize('multipath', [1])
@pytest.mark.parametrize('ipv4_routes', [8000])
@pytest.mark.parametrize('ipv6_routes', [4000])
@pytest.mark.parametrize('ipv6_prefix', [64])
def test_bgp_scalability_8kv4_4kv6_routes(cvg_api,          # noqa F811
                                          duthost,
                                          localhost,
                                          tgen_ports,       # noqa F811
                                          multipath,
                                          ipv4_routes,
                                          ipv6_routes,
                                          ipv6_prefix):

    run_bgp_scalability_v4_v6(cvg_api,
                              duthost,
                              localhost,
                              tgen_ports,
                              multipath,
                              ipv4_routes,
                              ipv6_routes,
                              ipv6_prefix)


@pytest.mark.parametrize('multipath', [1])
@pytest.mark.parametrize('ipv4_routes', [100000])
@pytest.mark.parametrize('ipv6_routes', [25000])
@pytest.mark.parametrize('ipv6_prefix', [64])
def test_bgp_scalability_100kv4_25kv6_routes(cvg_api,       # noqa F811
                                             duthost,
                                             localhost,
                                             tgen_ports,    # noqa F811
                                             multipath,
                                             ipv4_routes,
                                             ipv6_routes,
                                             ipv6_prefix):

    run_bgp_scalability_v4_v6(cvg_api,
                              duthost,
                              localhost,
                              tgen_ports,
                              multipath,
                              ipv4_routes,
                              ipv6_routes,
                              ipv6_prefix)


def test_cleanup_config(duthost):
    cleanup_config(duthost)
