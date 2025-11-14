"""
Test cases for SONiC counter functionality
"""
import pytest
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology('t0')
]


@pytest.fixture
def backup_and_cleanup_telemetry_groups(duthosts, rand_one_dut_hostname):
    """
    Fixture to backup HIGH_FREQUENCY_TELEMETRY_GROUP entries from CONFIG_DB before test
    and restore them after test completion.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Backup HIGH_FREQUENCY_TELEMETRY_GROUP entries
    backup_data = {}

    # Get all keys matching HIGH_FREQUENCY_TELEMETRY_GROUP pattern
    get_keys_result = duthost.shell(
        'redis-cli -n 4 --raw keys "*HIGH_FREQUENCY_TELEMETRY_GROUP*"',
        module_ignore_errors=True
    )

    if get_keys_result['rc'] == 0 and get_keys_result['stdout'].strip():
        keys = get_keys_result['stdout'].strip().split('\n')
        keys = [key.strip() for key in keys if key.strip()]

        # Backup each key's data
        for key in keys:
            # Get the hash data for each key
            get_data_result = duthost.shell(
                f'redis-cli -n 4 --raw hgetall "{key}"',
                module_ignore_errors=True
            )

            if get_data_result['rc'] == 0 and get_data_result['stdout'].strip():
                # Parse the hash data (redis returns field1 value1 field2 value2...)
                lines = get_data_result['stdout'].strip().split('\n')
                hash_data = {}
                for i in range(0, len(lines), 2):
                    if i + 1 < len(lines):
                        hash_data[lines[i]] = lines[i + 1]
                backup_data[key] = hash_data

    # Clear HIGH_FREQUENCY_TELEMETRY_GROUP entries
    if backup_data:
        for key in backup_data.keys():
            duthost.shell(
                f'redis-cli -n 4 --raw del "{key}"',
                module_ignore_errors=True
            )

    yield

    # Restore backed up data after test
    for key, hash_data in backup_data.items():
        if hash_data:
            # Restore hash data
            for field, value in hash_data.items():
                duthost.shell(
                    f'redis-cli -n 4 --raw hset "{key}" "{field}" "{value}"',
                    module_ignore_errors=True
                )


def test_counter_name_map(duthosts, rand_one_dut_hostname, backup_and_cleanup_telemetry_groups):
    """
    Test that COUNTERS_PG_NAME_MAP and COUNTERS_QUEUE_NAME_MAP exist in COUNTERS_DB

    This test verifies that the essential counter name mapping tables are present
    in the COUNTERS_DB (database 2) which are required for proper counter functionality.

    The test also cleans up HIGH_FREQUENCY_TELEMETRY_GROUP entries from CONFIG_DB
    before running and restores them afterward.

    Args:
        duthosts: Fixture providing list of DUT hosts
        rand_one_dut_hostname: Fixture providing a random DUT hostname
        backup_and_cleanup_telemetry_groups: Fixture to backup/restore telemetry groups
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Check if COUNTERS_PG_NAME_MAP exists
    pg_map_result = duthost.shell(
        'redis-cli -n 2 exists COUNTERS_PG_NAME_MAP',
        module_ignore_errors=True
    )

    # Check if COUNTERS_QUEUE_NAME_MAP exists
    queue_map_result = duthost.shell(
        'redis-cli -n 2 exists COUNTERS_QUEUE_NAME_MAP',
        module_ignore_errors=True
    )

    # Verify both maps exist (redis EXISTS returns 1 if key exists, 0 if not)
    pytest_assert(
        pg_map_result['stdout'].strip() == '1',
        "COUNTERS_PG_NAME_MAP does not exist in COUNTERS_DB"
    )

    pytest_assert(
        queue_map_result['stdout'].strip() == '1',
        "COUNTERS_QUEUE_NAME_MAP does not exist in COUNTERS_DB"
    )

    pg_count_result = duthost.shell(
        'redis-cli -n 2 hlen COUNTERS_PG_NAME_MAP',
        module_ignore_errors=True
    )

    queue_count_result = duthost.shell(
        'redis-cli -n 2 hlen COUNTERS_QUEUE_NAME_MAP',
        module_ignore_errors=True
    )

    pg_count = int(pg_count_result['stdout'].strip())
    queue_count = int(queue_count_result['stdout'].strip())

    pytest_assert(
        pg_count > 0,
        f"COUNTERS_PG_NAME_MAP exists but is empty (count: {pg_count})"
    )

    pytest_assert(
        queue_count > 0,
        f"COUNTERS_QUEUE_NAME_MAP exists but is empty (count: {queue_count})"
    )
