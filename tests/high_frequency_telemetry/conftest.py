import json
import logging
import time
from datetime import datetime

import pytest

from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

OTEL_CONFIG_PATH = "/etc/sonic/otel_config.yml"


@pytest.fixture(scope="module")
def suppress_otel_debug_logging(duthosts, enum_rand_one_per_hwsku_hostname):
    """Suppress verbose OTEL debug exporter logging to prevent /var/log disk exhaustion.

    The default OTEL collector config uses a debug exporter with 'verbosity: detailed',
    which dumps every metric (~14 lines each) to otel.log. During HFT tests with thousands
    of counters at 10ms polling, this generates ~40 million log lines in minutes and fills
    /var/log, causing rsyslog to drop messages (including LogAnalyzer markers).

    This fixture changes the verbosity to 'basic' (one summary line per batch) before
    HFT tests run, and restores the original config afterward.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Check if otel container is running
    if not duthost.is_container_running("otel"):
        logger.info("OTEL container is not running, skipping debug logging suppression")
        yield
        return

    # Read the current otel config
    result = duthost.shell(f'cat {OTEL_CONFIG_PATH}', module_ignore_errors=True)
    if result['rc'] != 0:
        logger.warning(f"Failed to read {OTEL_CONFIG_PATH}, skipping debug logging suppression")
        yield
        return

    original_config = result['stdout']

    if 'verbosity: detailed' not in original_config:
        logger.info("OTEL config does not have 'verbosity: detailed', no change needed")
        yield
        return

    # Change verbosity from detailed to basic
    logger.info("Changing OTEL debug exporter verbosity from 'detailed' to 'basic'")
    duthost.shell(
        f"sed -i 's/verbosity: detailed/verbosity: basic/' {OTEL_CONFIG_PATH}",
        module_ignore_errors=False
    )
    duthost.shell('docker restart otel', module_ignore_errors=True)
    wait_until(60, 2, 0, duthost.is_service_fully_started, "otel")

    yield

    # Restore original config
    logger.info("Restoring original OTEL collector config")
    duthost.copy(content=original_config, dest=OTEL_CONFIG_PATH)
    duthost.shell('docker restart otel', module_ignore_errors=True)
    wait_until(60, 2, 0, duthost.is_service_fully_started, "otel")


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthosts, enum_rand_one_per_hwsku_hostname, loganalyzer):
    """
    Ignore expected SAI_TAM errors during HFT test execution.

    When HFT is enabled, SONiC initially sends a buffer size of 65535 for IPFIX templates,
    but SAI requires a larger buffer (e.g., 119352). SAI returns SAI_STATUS_BUFFER_OVERFLOW
    with the required size, and SONiC retries with the correct size. This is normal behavior,
    not a functional issue. The error logs can be safely ignored.

    Args:
        duthosts: list of DUTs.
        enum_rand_one_per_hwsku_hostname: Hostname of a random chosen dut
        loganalyzer: Loganalyzer utility fixture
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if loganalyzer:
        ignoreRegex = [
            # SAI prints ERR when IPFIX template buffer is too small on first probe;
            # SONiC retries with the correct size and succeeds - not a functional issue
            ".*ERR syncd#SDK.*SAI_TAM.*mlnx_generate_ipfix_templates.*Buffer size is too small"
            " to hold IPFIX template.*",
            ".*ERR syncd#SDK.*SAI_TAM.*mlnx_tam_tel_type_get_ipfix_templates.*Failed to generate"
            " IPFIX templates.*",
            ".*ERR syncd#SDK.*SAI_TAM.*mlnx_tam_tel_type_attrib_get.*Failed to get attribute.*",
            ".*ERR syncd#SDK.*SAI_UTILS.*get_dispatch_attribs_handler.*Failed Get.*IPFIX_TEMPLATES.*",
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)


@pytest.fixture(scope="function")
def ensure_swss_ready(duthosts, enum_rand_one_per_hwsku_hostname):
    """Ensure swss container is running and stable for at least 10 seconds.

    Fail the test instead of restarting swss when the container state cannot be
    verified. A transient inspection error must not disrupt syncd or the SDK.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    def get_swss_uptime_seconds():
        """Get swss container uptime in seconds via docker inspect."""
        inspect_result = duthost.shell(
            "docker inspect swss",
            module_ignore_errors=True
        )
        if inspect_result['rc'] != 0:
            pytest.fail(
                "Failed to inspect swss container: {}".format(
                    inspect_result.get('stderr', '').strip()
                )
            )

        try:
            state = json.loads(inspect_result['stdout'])[0]['State']
            running = state['Running']
            started_at = state['StartedAt']
        except (json.JSONDecodeError, IndexError, KeyError, TypeError) as err:
            pytest.fail(
                "Unexpected docker inspect output for swss: {}".format(err)
            )

        if running is not True:
            pytest.fail(
                "swss container is not running "
                "(State.Running={})".format(running)
            )

        try:
            started_epoch = int(datetime.fromisoformat(
                started_at.replace('Z', '+00:00')
            ).timestamp())
        except (AttributeError, TypeError, ValueError) as err:
            pytest.fail("Invalid swss container start time: {}".format(err))

        uptime_result = duthost.shell(
            'date -u +%s',
            module_ignore_errors=True
        )
        if uptime_result['rc'] != 0:
            pytest.fail(
                "Failed to calculate swss container uptime: {}".format(
                    uptime_result.get('stderr', '').strip()
                )
            )

        try:
            uptime = int(uptime_result['stdout'].strip()) - started_epoch
        except ValueError:
            pytest.fail(
                "Unexpected swss container uptime: {!r}".format(
                    uptime_result['stdout'].strip()
                )
            )

        if uptime < 0:
            pytest.fail("swss container start time is in the future")

        logger.debug(f"swss container uptime: {uptime}s")
        return uptime

    logger.info("Checking swss container status...")

    # Check swss container uptime
    uptime = get_swss_uptime_seconds()
    min_uptime = 10  # Require at least 10 seconds uptime

    if uptime < min_uptime:
        wait_time = min_uptime - uptime + 1  # +1 for safety margin
        logger.info(f"swss container uptime is {uptime}s, "
                    f"waiting {wait_time}s for stability...")
        time.sleep(wait_time)
    else:
        logger.info(f"swss container is already stable "
                    f"(uptime: {uptime}s)")

    # Final verification
    final_uptime = get_swss_uptime_seconds()
    if final_uptime < min_uptime:
        raise RuntimeError(
            f"swss container uptime ({final_uptime}s) is still less "
            f"than required {min_uptime}s"
        )

    logger.info(
            f"swss container is ready and stable "
            f"(uptime: {final_uptime}s)"
        )


@pytest.fixture(scope="function")
def cleanup_high_frequency_telemetry(
    duthosts, enum_rand_one_per_hwsku_hostname, ensure_swss_ready,
    suppress_otel_debug_logging
):
    """
    Function-level fixture to clean up high frequency telemetry
    data before each test.
    This removes HIGH_FREQUENCY_TELEMETRY_PROFILE and
    HIGH_FREQUENCY_TELEMETRY_GROUP
    tables from CONFIG_DB (database 4) to ensure a clean state for testing.
    Depends on ensure_swss_ready to make sure swss container is stable.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logger.info("Cleaning up high frequency telemetry data...")

    # High frequency telemetry tables to clean from CONFIG_DB (database 4)
    hft_tables = [
        "HIGH_FREQUENCY_TELEMETRY_PROFILE",
        "HIGH_FREQUENCY_TELEMETRY_GROUP"
    ]

    total_deleted = 0

    for table in hft_tables:
        try:
            # Get all keys for this table using pattern matching
            keys_result = duthost.shell(
                f'redis-cli -n 4 keys "{table}|*"',
                module_ignore_errors=True
            )

            if keys_result['rc'] == 0 and keys_result['stdout'].strip():
                keys = [
                    key.strip() for key in keys_result['stdout_lines']
                    if key.strip()
                ]

                if keys:
                    # Delete all keys for this table
                    keys_str = ' '.join([f'"{key}"' for key in keys])
                    delete_result = duthost.shell(
                        f'redis-cli -n 4 del {keys_str}',
                        module_ignore_errors=True
                    )

                    if delete_result['rc'] == 0:
                        deleted_count = (
                            int(delete_result['stdout'].strip())
                            if delete_result['stdout'].strip().isdigit()
                            else 0
                        )
                        total_deleted += deleted_count
                        if deleted_count > 0:
                            logger.info(
                                f"Deleted {deleted_count} keys "
                                f"from table '{table}'"
                            )
                    else:
                        logger.warning(
                            f"Failed to delete keys from table '{table}'"
                        )
                else:
                    logger.debug(f"No keys found for table '{table}'")
            else:
                logger.debug(
                    f"No keys found for table '{table}' or command failed"
                )

        except Exception as e:
            logger.warning(f"Error cleaning up table '{table}': {e}")

    logger.info(
            f"High frequency telemetry cleanup completed. "
            f"Total keys deleted: {total_deleted}"
        )
