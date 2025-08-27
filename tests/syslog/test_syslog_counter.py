import logging
import pytest
import time

from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any")
]


@pytest.fixture(autouse=True, scope="module")
def enable_syslog_counter(rand_selected_dut):
    # Older version image may not support syslog counter feature
    yang = rand_selected_dut.command("sudo cat /usr/local/yang-models/sonic-device_metadata.yang")['stdout']
    if "syslog_counter" not in yang:
        pytest.skip("syslog_counter feature is not supported in this image.")
        return

    rand_selected_dut.command('sudo sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" "syslog_counter" "true"')
    rand_selected_dut.command('sudo config save -y')
    config_reload(rand_selected_dut, safe_reload=True)

    yield

    rand_selected_dut.command('sudo sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" "syslog_counter" "false"')
    rand_selected_dut.command('sudo config save -y')
    config_reload(rand_selected_dut, safe_reload=True)


def check_syslog_counter_updated(rand_selected_dut, old_value):
    new_value = rand_selected_dut.command("sonic-db-cli COUNTERS_DB hgetall SYSLOG_COUNTER")['stdout']
    return new_value != old_value


def test_syslog_counter(rand_selected_dut, enable_syslog_counter):
    """Test case for syslog counter

    Args:
        rand_selected_dut (object): DUT host object
    """
    old_value = rand_selected_dut.command("sonic-db-cli COUNTERS_DB hgetall SYSLOG_COUNTER")['stdout']

    rand_selected_dut.command('logger "test log"')

    pytest_assert(wait_until(120, 5, 0, check_syslog_counter_updated, rand_selected_dut, old_value),
                  "Syslog counter not update")
