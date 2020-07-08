# Helper Functions
import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any')
]

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
    features_dict, succeeded = duthost.get_feature_status()
    pytest_assert(succeeded, "failed to obtain feature status")
    for cmd_key, cmd_value in features_dict.items():
        feature = str(cmd_key)
        status_out = duthost.shell('/usr/bin/redis-cli -n 4 hgetall "FEATURE|{}"'.format(feature), module_ignore_errors=False)['stdout_lines']
        redis_value = get_status_redisout(status_out)
        status_value_expected = str(cmd_value)
        assert str(redis_value) == status_value_expected, "'{}' is '{}' which does not match with config_db".format(cmd_key, cmd_value)
