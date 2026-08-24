"""
    Pytest configuration used by the upgrade_strategy_fixture
"""
import logging

import pytest
from upgrade_strategies import create_upgrade_strategy
from utilities import HOST_METADATA_ARCHIVE, HOST_UPGRADE_SCRIPTS_ARCHIVE

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    """Add command line option for upgrade strategy selection."""
    parser.addoption(
        "--upgrade_strategy",
        action="store",
        default="script",
        choices=["script", "gnoi"],
        help="Strategy to use for firmware upgrade process: script (default) or gnoi"
    )


@pytest.fixture(scope="module")
def upgrade_strategy_fixture(request, ptfhost):
    """
    Pytest fixture to create upgrade strategy based on command-line option.

    Args:
        request: Pytest request object for accessing command-line options
        ptfhost: PTF host fixture for gNOI-based strategies

    Returns:
        UpgradeStrategy instance
    """
    strategy_type = request.config.getoption('upgrade_strategy', default='script')

    if strategy_type == 'script':
        return create_upgrade_strategy('script')
    elif strategy_type == 'gnoi':
        # Import ptf_gnoi here to avoid circular dependency
        from tests.common.ptf_gnoi import PtfGnoi
        ptf_gnoi = PtfGnoi(ptfhost)
        return create_upgrade_strategy('gnoi', ptf_gnoi)
    else:
        raise ValueError(f"Unknown upgrade strategy '{strategy_type}'. Valid options: script, gnoi")


@pytest.fixture(scope="module", autouse=True)
def cleanup_staged_script_archives(request):
    """Remove staged script archives after each metadata test module."""
    if request.config.getoption("metadata_process"):
        duthosts = request.getfixturevalue("duthosts")
    else:
        duthosts = []

    yield

    for duthost in duthosts:
        for archive in (HOST_METADATA_ARCHIVE, HOST_UPGRADE_SCRIPTS_ARCHIVE):
            try:
                duthost.file(path=archive, state="absent", module_ignore_errors=True)
            except Exception as exc:
                logger.warning(
                    "Failed to remove %s from %s: %s",
                    archive,
                    duthost.hostname,
                    exc,
                )
