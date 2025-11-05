import logging
import pytest
import random
import time

from tests.common.config_reload import config_reload
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor

pytestmark = [
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
    pytest.mark.topology('any'),  # This test is not topology dependent
    pytest.mark.stress_test  # Use --run-stress-tests to run this test
]

LOWER_DELAY_BETWEEN_LOAD_MG = 120  # 2 minutes
UPPER_DELAY_BETWEEN_LOAD_MG = 300  # 5 minutes
TIMES_TO_RUN = 25

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("run", range(TIMES_TO_RUN))
def test_load_minigraph_consecutive_small_delay(duthosts, run):
    """
    Runs load minigraph on DUTs (in randomised order) with small random delay between each
    Each DUT will have safe reload to check that critical proccesses/BGP/interfaces etc. are all up
    """
    duthosts_random = random.sample(list(duthosts.frontend_nodes), len(duthosts.frontend_nodes))
    logger.info("Randomized DUT order: {}".format(duthosts_random))

    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for i, duthost in enumerate(duthosts_random):
            # Safe reload to make sure critical processes is up
            logger.info("Performing load_minigraph on DUT {}".format(duthost.hostname))
            executor.submit(
                config_reload,
                duthost, config_source='minigraph', safe_reload=True, check_intf_up_ports=True,
                wait_for_bgp=True
            )
            # Skip delay for the last DUT
            if i < len(duthosts_random) - 1:
                delay = random.randrange(LOWER_DELAY_BETWEEN_LOAD_MG, UPPER_DELAY_BETWEEN_LOAD_MG+1)
                logger.info("Delay for {} seconds before next action".format(delay))
                time.sleep(delay)

    logger.info("All DUTs have completed load_minigraph")
