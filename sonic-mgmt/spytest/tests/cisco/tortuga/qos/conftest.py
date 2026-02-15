import pytest
from spytest import st


@pytest.fixture(scope="module", autouse=True)
def config_cleanup():
    yield
    # Skip rollback - QoS tests handle their own cleanup
