import os
import sys
import pytest
from spytest import st

# Add infra/ to sys.path so all test subdirectories can do bare imports
# (e.g., import qos_test_utils, import traffic_stream_ixia_api)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'infra'))


@pytest.fixture(scope="module", autouse=True)
def config_cleanup():
    yield
    # Skip rollback - QoS tests handle their own cleanup
