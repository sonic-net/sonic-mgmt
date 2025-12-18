"""
Minimal conftest.py for sample tests.

This conftest provides minimal fixtures to allow sample tests to run
without requiring the full sonic-mgmt test infrastructure.
"""
import pytest
from unittest.mock import MagicMock


# Prevent loading the parent conftest.py which has heavy dependencies
# This allows the sample tests to run standalone for testing the plugin


@pytest.fixture(scope="session")
def testbed(request):
    """Mock testbed fixture for sample tests."""
    return "sample-testbed"


@pytest.fixture(scope="session")
def tbinfo(request):
    """Mock testbed info fixture."""
    return {
        'topo': {
            'name': 't0',
            'type': 't0'
        },
        'duts': ['localhost']
    }


@pytest.fixture
def duthosts():
    """Mock duthosts fixture."""
    return MagicMock()


@pytest.fixture
def duthost():
    """Mock duthost fixture."""
    return MagicMock()


@pytest.fixture
def localhost():
    """Mock localhost fixture."""
    return MagicMock()


def pytest_configure(config):
    """
    Configure pytest for sample tests.
    """
    # Set default options if not provided
    if not config.getoption("--testbed", None):
        config.option.testbed = "sample-testbed"

    if not config.getoption("--testbed_file", None):
        config.option.testbed_file = "testbed.yaml"

    if not config.getoption("--inventory", None):
        config.option.inventory = "../ansible/lab"
