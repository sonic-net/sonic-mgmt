"""
Pytest configuration used by the link flap tests.

Teardowns used by the link flap tests.
"""
import pytest
def pytest_addoption(parser):
    """
    Adds options to pytest that are used by the Link flap tests.
    """

    parser.addoption(
        "--orch_cpu_threshold",
        action="store",
        type=int,
        default=10,
        help="Orchagent CPU threshold",
    )

@pytest.fixture(scope='module')
def get_function_conpleteness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")
