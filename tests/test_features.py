# Helper Functions
import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any')
]

# Test Functions
def test_show_features(duthosts, enum_dut_hostname):
    """Verify show features command output against CONFIG_DB
    """
    duthost = duthosts[enum_dut_hostname]
    features_dict, succeeded = duthost.get_feature_status()
    pytest_assert(succeeded, "failed to obtain feature status")
    for cmd_key, cmd_value in features_dict.items():
        feature = str(cmd_key)
        redis_value = duthost.shell('/usr/bin/redis-cli -n 4 --raw hget "FEATURE|{}" "state"'.format(feature), module_ignore_errors=False)['stdout']
        pytest_assert(redis_value.lower() == cmd_value.lower(), "'{}' is '{}' which does not match with config_db".format(cmd_key, cmd_value))
