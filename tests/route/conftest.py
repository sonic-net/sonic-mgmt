import pytest


# Pytest configuration used by the route tests.
def pytest_addoption(parser):
    # Add options to pytest that are used by route tests

    route_group = parser.getgroup("Route test suite options")

    route_group.addoption("--num_routes", action="store", default=None, type=int,
                          help="Number of routes for add/delete")

    route_group.addoption("--max_scale", action="store_true",
                          help="Test with maximum possible route scale")


@pytest.fixture(scope='module')
def get_function_conpleteness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")
