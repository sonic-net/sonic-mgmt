"""
Test cases for SONiC counter functionality
"""
import pytest
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology('t0')
]


def test_counter_name_map(duthosts, rand_one_dut_hostname):
    """
    Test that COUNTERS_PG_NAME_MAP and COUNTERS_QUEUE_NAME_MAP exist in COUNTERS_DB

    This test verifies that the essential counter name mapping tables are present
    in the COUNTERS_DB (database 2) which are required for proper counter functionality.

    Args:
        duthosts: Fixture providing list of DUT hosts
        rand_one_dut_hostname: Fixture providing a random DUT hostname
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
