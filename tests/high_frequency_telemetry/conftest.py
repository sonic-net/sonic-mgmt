import pytest
import logging
import time

logger = logging.getLogger(__name__)


@pytest.fixture(scope="function")
def ensure_swss_ready(duthosts, enum_rand_one_per_hwsku_hostname):
    """Ensure swss container is running and stable for at least 10 seconds.

    Function-level fixture that runs before each test to ensure swss is ready,
    as tests may affect the container state.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    def get_swss_uptime_seconds():
        """Get swss container uptime in seconds from docker ps"""
        try:
            # Use docker ps to get status info - avoid template conflicts
            result = duthost.shell(
                'docker ps --filter "name=swss"',
                module_ignore_errors=True
            )
            if result['rc'] != 0:
                return 0

            stdout_lines = result['stdout_lines']
            if len(stdout_lines) < 2:  # No container found (only header)
                return 0

            # Find the swss container line and extract status
            for line in stdout_lines[1:]:  # Skip header
                if 'swss' in line:
                    # Line format: CONTAINER_ID IMAGE COMMAND
                    # CREATED STATUS PORTS NAMES
                    # Example: d0a33fe4d37f docker-orchagent:latest
                    # "/usr/bin/docker-ini…" 8 days ago Up 18 minutes swss
                    parts = line.split()

                    # Find "Up" and get the next parts for time
                    try:
                        up_index = parts.index('Up')
                        if up_index + 2 < len(parts):
                            time_value = parts[up_index + 1]
                            time_unit = parts[up_index + 2]

                            logger.debug(f"swss container status: "
                                         f"Up {time_value} {time_unit}")

                            # Convert to seconds
                            time_num = int(time_value)
                            if 'second' in time_unit:
                                return time_num
                            elif 'minute' in time_unit:
                                return time_num * 60
                            elif 'hour' in time_unit:
                                return time_num * 3600
                            elif 'day' in time_unit:
                                return time_num * 86400
                            else:
                                return 20  # Unknown format, assume long enough
                    except (ValueError, IndexError):
                        logger.warning(f"Failed to parse status line: {line}")
                        return 0

            return 0  # No swss container found

        except Exception as e:
            logger.warning(f"Failed to get swss uptime: {e}")
            return 0

    logger.info("Checking swss container status...")

    # Check swss container uptime
    uptime = get_swss_uptime_seconds()
    min_uptime = 10  # Require at least 10 seconds uptime

    if uptime == 0:
        logger.warning("swss container is not running, attempting to start...")

        # Try to restart swss service
        duthost.shell('sudo systemctl restart swss',
                      module_ignore_errors=True)

        # Wait for container to start and stabilize
        max_wait = 40  # Total wait time
        logger.info(f"Waiting up to {max_wait} seconds for swss container "
                    f"to start and stabilize...")

        for i in range(max_wait):
            time.sleep(1)
            current_uptime = get_swss_uptime_seconds()
            if current_uptime >= min_uptime:
                logger.info(f"swss container is stable "
                           f"(uptime: {current_uptime}s)")
                break
        else:
            raise RuntimeError(f"swss container failed to stabilize "
                              f"after {max_wait} seconds")

    elif uptime < min_uptime:
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
    duthosts, enum_rand_one_per_hwsku_hostname, ensure_swss_ready
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


@pytest.fixture(scope="function")
def disable_flex_counters(
    duthosts, enum_rand_one_per_hwsku_hostname,
    cleanup_high_frequency_telemetry
):
    """
    Function-level fixture to disable all flex counters and restore
    them after each test.
    Depends on cleanup_high_frequency_telemetry to ensure clean state.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Get all flex counter tables
    flex_counter_keys = duthost.shell(
        'redis-cli -n 4 keys "FLEX_COUNTER_TABLE|*"',
        module_ignore_errors=False
    )['stdout_lines']

    # Store original states
    original_states = {}
    for key in flex_counter_keys:
        if key.strip():  # Skip empty lines
            table_name = key.strip()
            status = duthost.shell(
                f'redis-cli -n 4 HGET "{table_name}" "FLEX_COUNTER_STATUS"',
                module_ignore_errors=False
            )['stdout'].strip()
            original_states[table_name] = status

            # Disable the flex counter
            duthost.shell(
                f'redis-cli -n 4 HSET "{table_name}" '
                f'"FLEX_COUNTER_STATUS" "disable"',
                module_ignore_errors=False
            )

    logger.info(f"Disabled {len(original_states)} flex counters")

    yield

    # Restore original states
    for table_name, status in original_states.items():
        if status:  # Only restore if there was an original status
            duthost.shell(
                f'redis-cli -n 4 HSET "{table_name}" '
                f'"FLEX_COUNTER_STATUS" "{status}"',
                module_ignore_errors=False
            )

    logger.info("Restored all flex counters to original states")
