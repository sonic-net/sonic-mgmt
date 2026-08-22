import logging
import pytest

from .nasa_debug_utils import (  # noqa: F401 - re-exported public API
    NASA_DEBUG_ENTITY,
    NASA_DEBUG_DUMP_DIR,
    nasa_entity_debug_set,
    get_nasa_entity_debug_enabled,
    get_nasa_entity_debug_file,
    nasa_debuggability_enable,
    nasa_debuggability_disable,
    nasa_debuggability_enable_all,
    nasa_debuggability_disable_all,
    get_file_size,
    nasa_ct_dump_set,
    get_nasa_ct_dump_enabled,
    NASA_CT_DUMP_SENTINEL,
    NASA_CT_DUMP_FILES,
    NASA_FLOW_DUMP_PATTERN,
    NASA_MST_DUMP_PATTERNS,
    get_techsupport_file_list,
)

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    """Add --nasa_debug command line option to pytest."""
    parser.addoption(
        "--nasa_debug",
        action="store_true",
        help="Turn on NASA debuggability for the tests to enable the debug info in the tech support."
    )


def pytest_configure(config):
    if config.getoption("--nasa_debug"):
        config.pluginmanager.import_plugin("tests.common.plugins.nasa_debug.nasa_debug_fixtures")


@pytest.fixture(scope="session", autouse=True)
def nasa_debug(request):
    """Session-scoped fixture that returns the --nasa_debug option value."""
    logger.info("Fixture NASA debug: {}".format(request.config.getoption("--nasa_debug")))
    return request.config.getoption("--nasa_debug")
