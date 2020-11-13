from tests.common.helpers.assertions import pytest_assert
import pytest

pytestmark = [
    pytest.mark.topology('any')
]

# Helper Functions
def get_count_fromredisout(keys_out):
    """Extract keys count from redis output
    """
    count = ""
    for s in keys_out:
        count = s.encode('UTF-8')
        return count

# Test Functions
def test_verify_status(duthosts, rand_one_dut_hostname):
    """Verify procdockerstatsd is active and running
    """
    duthost = duthosts[rand_one_dut_hostname]
    status = duthost.get_service_props('procdockerstatsd')
    pytest_assert(status["ActiveState"] == "active" and status["SubState"] == "running", "Procdockerstatsd either not active or not running")

def test_verify_redisexport(duthosts, rand_one_dut_hostname):
    """Verify procdockerstatsd is exporting values to redis.
    """
    duthost = duthosts[rand_one_dut_hostname]
    docker_stdout = duthost.shell('/usr/bin/redis-cli -n 6 KEYS "DOCKER_STATS|*" | wc -l', module_ignore_errors=False)['stdout_lines']
    docker_keys_count = get_count_fromredisout(docker_stdout)
    process_stdout= duthost.shell('/usr/bin/redis-cli -n 6 KEYS "PROCESS_STATS|*" | wc -l', module_ignore_errors=False)['stdout_lines']
    process_keys_count = get_count_fromredisout(process_stdout)
    # if entry for process or docker data found then daemon is upload is sucessful
    pytest_assert(int(docker_keys_count) > 1, "No data docker data upload found by Procdockerstatsd daemon to state_db")
    pytest_assert(int(process_keys_count) > 1, "No data process data upload found by Procdockerstatsd daemon to state_db")
