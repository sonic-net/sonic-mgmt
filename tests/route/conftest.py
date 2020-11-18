# Pytest configuration used by the route tests.
def pytest_addoption(parser):
    # Add options to pytest that are used by route tests

    route_group = parser.getgroup("Route test suite options")

    route_group.addoption("--num_routes", action="store", default=10000, type=int,
                     help="Number of routes for add/delete")
