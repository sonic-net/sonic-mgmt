
import logging
import yaml

import pytest

from os import path

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    """
    Adds pytest options that are used by DASH tests
    """

    parser.addoption(
        "--skip_config",
        action="store_true",
        help="Apply new configurations on DUT"
    )

    parser.addoption(
        "--config_only",
        action="store_true",
        help="Apply new configurations on DUT"
    )

@pytest.fixture(scope="module")
def config_only(request):
    return request.config.getoption("--config_only")

@pytest.fixture(scope="module")
def skip_config(request):
    return request.config.getoption("--skip_config")

@pytest.fixture(scope="module")
def minigraph_facts(duthosts, rand_one_dut_hostname, tbinfo):
    """
    Fixture to get minigraph facts

    Args:
        duthost: DUT host object

    Returns:
        Dictionary containing minigraph information
    """
    duthost = duthosts[rand_one_dut_hostname]

    return duthost.get_extended_minigraph_facts(tbinfo)
