import pytest
from tests.common import constants


# Pytest configuration used by the route tests.
def pytest_addoption(parser):
    # Add options to pytest that are used by route tests

    route_group = parser.getgroup("Route test suite options")

    route_group.addoption("--num_routes", action="store", default=None, type=int,
                          help="Number of routes for add/delete")

    route_group.addoption("--max_scale", action="store_true",
                          help="Test with maximum possible route scale")


@pytest.fixture(scope='module')
def get_function_completeness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")


@pytest.fixture(scope='module', params=[4, 6])
def ip_versions(request):
    """
    Parameterized fixture for IP versions.
    """
    yield request.param


@pytest.fixture(scope="module")
def is_backend_topology(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
        Check if the current test is running on the backend topology.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    is_backend_topology = mg_facts.get(constants.IS_BACKEND_TOPOLOGY_KEY, False)

    return is_backend_topology
