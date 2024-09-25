import pytest


@pytest.fixture(scope='module')
def get_function_completeness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")


def pytest_configure(config):
    config.asic_db = dict()
