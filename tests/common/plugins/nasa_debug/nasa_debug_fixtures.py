import pytest
import logging
from .nasa_debug_utils import nasa_debuggability_enable_all, nasa_debuggability_disable_all

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True, scope="module")
def enable_nasa_debuggability(request, dpuhosts):
    """Automatically enable NASA debuggability before each test module.

    This fixture enables NASA debug on all DPUs before the test module runs
    and disables it after the module completes.

    Args:
        request: pytest request object
        dpuhosts: List of DPU host objects (from SmartSwitch fixture)
    """
    # for DASH tests, enable the debuggability on all DPUs
    logger.info("Enabling NASA debuggability to capture tech support info")
    nasa_debuggability_enable_all(dpuhosts)

    yield

    # for DASH tests, disable the debuggability on all DPUs
    logger.info("Disabling NASA debuggability to capture tech support info")
    nasa_debuggability_disable_all(dpuhosts)
