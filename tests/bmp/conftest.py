
def pytest_addoption(parser):
    parser.addoption("--container_test", action="store", default="",
                     help="This flag indicates that the test is being run by the container test.")
