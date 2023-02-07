import pytest


@pytest.fixture(scope='module')
def get_function_conpleteness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")
