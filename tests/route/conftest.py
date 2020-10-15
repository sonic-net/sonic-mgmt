# Pytest configuration used by the route tests.
def pytest_addoption(parser):
    # Add options to pytest that are used by route tests
    parser.addoption("--num_routes", action="store", default=10000, type=int,
                     help="Number of routes for add/delete")
