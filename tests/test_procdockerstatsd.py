
#Helper Functions
def get_count_fromredisout(keys_out):
    """Extract keys count from redis output
    """
    count = ""
    for s in keys_out:
        count = s.encode('UTF-8')
        return count

#Test Functions
def test_verify_status(duthost):
    """Verify procdockerstatsd is active and running
    """
    status = duthost.get_service_props('procdockerstatsd')
    if status["ActiveState"] == "active" and status["SubState"] == "running":
        assert True , "Procdockerstatsd is active and running"

def test_verify_redisexport(duthost):
    """Verify procdockerstatsd is exporting values to redis.
    """
    docker_stdout = duthost.shell('/usr/bin/redis-cli -n 6 KEYS "DOCKER_STATS|*" | wc -l' , module_ignore_errors=False)['stdout_lines']
    docker_keys_count = get_count_fromredisout(docker_stdout)
    process_stdout= duthost.shell('/usr/bin/redis-cli -n 6 KEYS "PROCESS_STATS|*" | wc -l' , module_ignore_errors=False)['stdout_lines']
    process_keys_count = get_count_fromredisout(process_stdout)
    #if single entry found then daemon is upload is sucessful
    if int(docker_keys_count) > 1 and int(process_keys_count) > 1:
        assert True, "Procdockerstatsd is uploading data to state_db"
