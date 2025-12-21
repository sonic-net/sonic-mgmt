import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any")
]


def check_syslog_counter_updated(rand_selected_dut, old_value):
    new_value = rand_selected_dut.command("sonic-db-cli COUNTERS_DB hgetall SYSLOG_COUNTER")['stdout']
    return new_value > old_value


def test_syslog_counter(rand_selected_dut):
    """Test case for syslog counter

    Args:
        rand_selected_dut (object): DUT host object
    """
    # Older version image may not support syslog counter feature
    # Syslog counter feature enabled by default in ansible/library/generate_golden_config_db.py
    yang = rand_selected_dut.command("sudo cat /usr/local/yang-models/sonic-device_metadata.yang")['stdout']
    if "syslog_counter" not in yang:
        pytest.skip("syslog_counter feature is not supported in this image.")
        return

    old_value = rand_selected_dut.command("sonic-db-cli COUNTERS_DB hgetall SYSLOG_COUNTER")['stdout']

    rand_selected_dut.command('logger "test log"')

    pytest_assert(wait_until(120, 5, 0, check_syslog_counter_updated, rand_selected_dut, old_value),
                  "Syslog counter not update")
