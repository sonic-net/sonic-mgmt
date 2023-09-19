def pytest_addoption(parser):
    parser.addoption("--unresettable_xcvr_types", action="append", default=[], help="unsupported resettable xcvr types")
