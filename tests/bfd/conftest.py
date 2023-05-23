def pytest_addoption(parser):
    parser.addoption("--num_sessions", action="store", default=5)
    parser.addoption("--num_sessions_scale", action="store", default=128)
