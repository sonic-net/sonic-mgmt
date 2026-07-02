import json
import logging
import time
import pytest
import re

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, expect_op_success
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.gu_utils import get_gcu_timeout

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

CHECK_INTERVAL = 60  # Interval (in seconds) for polling command readiness


@pytest.fixture(autouse=True)
def ensure_dut_readiness(duthosts, rand_one_dut_front_end_hostname):
    """
    Setup/teardown fixture for each test.
    Rollback to original checkpoint after the test.
    """
    duthost = duthosts[rand_one_dut_front_end_hostname]
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


def apply_patch_async(duthost, json_data, dest_file, timeout, check_interval=CHECK_INTERVAL):
    """Apply a GCU patch asynchronously with periodic timeout checks.

    Follows the async polling pattern from test_reload_config.py:
    runs duthost.shell with module_async=True, then polls for completion
    so the test can fail at the timeout boundary instead of blocking for
    the full duration of a hung command.

    Returns:
        tuple: (output, elapsed) where output is the shell result dict
               and elapsed is wall-clock seconds.
    Raises:
        TimeoutError: if the command does not complete within *timeout* seconds.
    """
    patch_content = json.dumps(json_data, indent=4)
    duthost.copy(content=patch_content, dest=dest_file)
    logger.debug("Patch content: {}".format(patch_content))

    cmds = 'config apply-patch {}'.format(dest_file)
    logger.info("Running async: {}".format(cmds))

    start_time = time.time()
    pool, async_result = duthost.shell(cmds, module_ignore_errors=True, module_async=True)

    try:
        while not async_result.ready():
            elapsed = time.time() - start_time
            if elapsed > timeout:
                logger.error(
                    "apply-patch not completed after {:.1f}s (timeout {}s) — aborting".format(
                        elapsed, timeout
                    )
                )
                pool.terminate()
                raise TimeoutError(
                    "Patch operation did not complete in {}s. Elapsed: {:.1f}s".format(
                        timeout, elapsed
                    )
                )
            logger.debug("apply-patch still running, elapsed {:.1f}s".format(elapsed))
            time.sleep(check_interval)

        elapsed = time.time() - start_time

        if async_result.successful():
            output = async_result.get()
            logger.info("apply-patch finished in {:.1f}s".format(elapsed))
            return output, elapsed

        # The thread raised an exception — re-raise it so the test fails
        # with the original traceback.
        output = async_result.get()
        # async_result.get() re-raises; this line is unreachable but keeps
        # the return type consistent for static analysis.
        return output, elapsed
    finally:
        pool.terminate()
        pool.join()


def test_gcu_acl_ports_replace_large_to_small(duthosts, rand_one_dut_front_end_hostname):
    """Test that GCU apply-patch completes within expected time when replacing
    a large ACL ports list with a small one.

    Validates that GCU's internal sorting / diff logic does not hang when a
    large port list is replaced with a much smaller one.
    """
    duthost = duthosts[rand_one_dut_front_end_hostname]

    # gcu_timeout is platform-specific; looked up from GCUTIMEOUT_MAP in
    # gu_utils.py, defaulting to 600s.  Used both as the async polling
    # deadline and the final elapsed-time assertion.
    gcu_timeout = get_gcu_timeout(duthost)

    config_facts = duthost.config_facts(
        host=duthost.hostname,
        source="running",
        verbose=False
    )['ansible_facts']

    ports = sorted(
        config_facts.get('PORT', {}).keys(),
        key=lambda p: int(re.search(r'\d+', p).group())
    )

    if len(ports) < 4:
        pytest.skip("Not enough ports available on DUT (need at least 4, found {})".format(len(ports)))

    logger.info("DUT has {} ports: {} … {}".format(len(ports), ports[0], ports[-1]))

    # --- Step 1: Add ACL table bound to ALL available ports (precondition) ---
    add_table_patch = [
        {
            "op": "add",
            "path": "/ACL_TABLE/GCU_HANG_TEST_TABLE",
            "value": {
                "policy_desc": "GCU_HANG_TEST_TABLE",
                "type": "L3",
                "stage": "ingress",
                "ports": ports
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    try:
        logger.info("Adding ACL table with {} ports".format(len(ports)))
        output = apply_patch(duthost, json_data=add_table_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

    # --- Step 2: Replace ports list (large → small) with async monitoring ---
    small_ports = ports[:2]
    logger.info("Replacing ports: {} → {} ({})".format(len(ports), len(small_ports), small_ports))

    replace_ports_patch = [
        {
            "op": "replace",
            "path": "/ACL_TABLE/GCU_HANG_TEST_TABLE/ports",
            "value": small_ports
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    try:
        output, elapsed = apply_patch_async(
            duthost, replace_ports_patch, tmpfile, timeout=gcu_timeout
        )
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

    logger.info("GCU ACL ports replace took {:.1f}s (timeout: {}s)".format(elapsed, gcu_timeout))
    pytest_assert(
        elapsed < gcu_timeout,
        "GCU apply-patch for ACL ports replace took {:.1f}s, exceeded timeout {}s. "
        "Likely GCU sorting hang on large-to-small list replace.".format(elapsed, gcu_timeout)
    )
