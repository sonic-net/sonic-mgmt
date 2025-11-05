import logging
import pytest


from tests.common.config_reload import config_reload
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor

pytestmark = [
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
    pytest.mark.topology('any'),  # This test is not topology dependent
    pytest.mark.stress_test  # Use --run-stress-tests to run this test
]

TIMES_TO_RUN = 25

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("run", range(TIMES_TO_RUN))
def test_config_reload_parallel(duthosts, run):
    """
    Runs config reload on all DUTs in parallel
    Each DUT will have safe reload to check that critical proccesses/BGP/interfaces etc. are all up
    """
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in duthosts:
            logger.info("Performing config reload on DUT {}".format(duthost.hostname))
            # Safe reload to make sure critical processes is up
            executor.submit(
                config_reload,
                duthost, config_source='config_db', safe_reload=True, check_intf_up_ports=True,
                wait_for_bgp=True
            )

    logger.info("All DUTs have completed config reload")
