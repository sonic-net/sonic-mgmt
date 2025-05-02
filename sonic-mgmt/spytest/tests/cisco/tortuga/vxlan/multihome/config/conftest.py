import pytest


@pytest.fixture(scope="module", autouse=True)
def setup(configure):
    """
    This fixture is used to setup the configuration for the test.
    It loads the configuration from the specified file and applies it.
    """
    yield configure
