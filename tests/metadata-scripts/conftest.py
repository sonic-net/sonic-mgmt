"""
    Pytest configuration used by the upgrade_strategy_fixture
"""


def pytest_addoption(parser):
    """Add command line option for upgrade strategy selection."""
    parser.addoption(
        "--upgrade_strategy",
        action="store",
        default="script",
        choices=["script", "gnoi"],
        help="Strategy to use for firmware upgrade process: script (default) or gnoi"
    )
