# Helper Functions
def get_dict_stdout(cmd_out):
    """Extract dictionary from show features command output
    """
    result = ""
    out_dict = {}
    cmd = cmd_out[2:]
    for x in cmd:
        result = x.encode('UTF-8')
        r = result.split()
        out_dict[r[0]] = r[1]
    return out_dict

def get_status_redisout(status_out):
    """Extract status value for feature in redis
    """
    status_list = status_out[1:]
    status = ""
    for s in status_list:
        status = s.encode('UTF-8')
        return status

# Test Functions
def test_show_features(duthost):
    """Verify show features command output against CONFIG_DB
    """
    features_stdout = duthost.shell('show features', module_ignore_errors=False)['stdout_lines']
    features_dict = get_dict_stdout(features_stdout)
    for cmd_key, cmd_value in features_dict.items():
        feature = str(cmd_key)
        status_out = duthost.shell('/usr/bin/redis-cli -n 4 hgetall "FEATURE|{}"'.format(feature), module_ignore_errors=False)['stdout_lines']
        redis_value = get_status_redisout(status_out)
        status_value_expected = str(cmd_value)
        assert str(redis_value) == status_value_expected, "'{}' is '{}' which does not match with config_db".format(cmd_key, cmd_value)
