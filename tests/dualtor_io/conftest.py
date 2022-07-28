def pytest_configure(config):

    config.addinivalue_line(
        "markers", "enable_active_active: mark test to run with 'active_standby' ports"
    )
