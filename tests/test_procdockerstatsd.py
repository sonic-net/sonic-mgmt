from common.helpers.assertions import pytest_assert

# Helper Functions
def get_count_fromredisout(keys_out):
    """Extract keys count from redis output
    """
    count = ""
    for s in keys_out:
        count = s.encode('UTF-8')
        return count

# Test Functions
def test_verify_status(duthost):
    """Verify procdockerstatsd is active and running
    """
    status = duthost.get_service_props('procdockerstatsd')
    pytest_assert(status["ActiveState"] == "active" and status["SubState"] == "running", "Procdockerstatsd either not active or not running")

def test_verify_redisexport(duthost):
    """Verify procdockerstatsd is exporting values to redis.
    """
    docker_stdout = duthost.shell('/usr/bin/redis-cli -n 6 KEYS "DOCKER_STATS|*" | wc -l', module_ignore_errors=False)['stdout_lines']
    docker_keys_count = get_count_fromredisout(docker_stdout)
    process_stdout= duthost.shell('/usr/bin/redis-cli -n 6 KEYS "PROCESS_STATS|*" | wc -l', module_ignore_errors=False)['stdout_lines']
    process_keys_count = get_count_fromredisout(process_stdout)
    # if entry for process or docker data found then daemon is upload is sucessful
    pytest_assert(int(docker_keys_count) > 1, "No data docker data upload found by Procdockerstatsd daemon to state_db")
    pytest_assert(int(process_keys_count) > 1, "No data process data upload found by Procdockerstatsd daemon to state_db")
