import pytest
from tests.snappi_tests.dualtor.utilities import set_tunnel_qos_remap_multidut
import logging

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def on_test_end_enable_tunnel_qos_remap(duthosts):
    """
    Reset tunnel_qos_remap to a good state. Helpful to forcefully reset rather than
    preserve the original settings for cases when test failures corrupt the running state.
    May not be needed if a hard reset is being performed on config db.
    """
    yield
    logger.info("On test exit, checking whether dualtor libra needs to reset tunnel_qos_remap to true")
    set_tunnel_qos_remap_multidut(duthosts, True)
