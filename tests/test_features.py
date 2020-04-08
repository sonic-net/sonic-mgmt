import pytest
import logging

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

def test_show_features(duthost):
    """Verify show features command output against CONFIG_DB
    """
    features_stdout = duthost.shell('show features', module_ignore_errors=False)['stdout_lines']
    features_dict = get_dict_stdout(features_stdout)
    for k,v in features_dict.items():
        feature = str(k)
        status_out = duthost.shell('/usr/bin/redis-cli -n 4 hgetall "FEATURE|{}"'.format(feature), module_ignore_errors=False)['stdout_lines']
        redis_value = get_status_redisout(status_out)
        if str(redis_value) == str(v):
            assert True, "{} is {} which matches with config_db".format(k,v)
