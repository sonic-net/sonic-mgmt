import logging
import json
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_res_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.generic_config_updater.gu_utils import is_valid_platform_and_version

pytestmark = [
    pytest.mark.asic('mellanox'),
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

READ_FLEXCOUNTER_DB_TIMEOUT = 480
READ_FLEXCOUNTER_DB_INTERVAL = 20


@pytest.fixture(scope="module")
def ensure_dut_readiness(duthost):
    """
    Setup/teardown fixture for pfcwd interval config update tst

    Args:
        duthost: DUT host object
    """
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original  checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


def ensure_application_of_updated_config(duthost, value):
    """
    Ensures application of the JSON patch config update by verifying field value presence in FLEX COUNTER DB

    Args:
        duthost: DUT host object
        value: expected value of POLL_INTERVAL
    """
    def _confirm_value_in_flex_counter_db():
        poll_interval = duthost.shell('sonic-db-cli PFC_WD_DB hget FLEX_COUNTER_GROUP_TABLE:PFC_WD POLL_INTERVAL')["stdout"]
        return value == poll_interval

    pytest_assert(
        wait_until(READ_FLEXCOUNTER_DB_TIMEOUT, READ_FLEXCOUNTER_DB_INTERVAL, 0, _confirm_value_in_flex_counter_db),
        "FLEX COUNTER DB does not properly reflect newly POLL_INTERVAL expected value: {}".format(value)
    )


def prepare_pfcwd_interval_config(duthost, value):
    """
    Prepares config db by setting pfcwd poll interval to specified value. If value is empty string, delete the current entry.

    Args:
        duthost: DUT host object
        value: poll interval value to be set
    """

    logger.info("Setting configdb entry pfcwd poll interval to value: {}".format(value))

    if value:
        cmd = "pfcwd interval {}".format(value)
    else:
        cmd = "sonic-db-cli CONFIG_DB del \PFC_WD\GLOBAL\POLL_INTERVAL"

    duthost.shell(cmd)


def get_detection_restoration_times(duthost):
    """
    Returns detection_time, restoration_time for an interface. Poll_interval must be greater than both in order to be valid

    Args:
        duthost: DUT host object
    """

    duthost.shell('config pfcwd start --action drop all 400 --restoration-time 400', module_ignore_errors=True)
    pfcwd_config = duthost.shell("show pfcwd config")
    pytest_assert(not pfcwd_config['rc'], "Unable to read pfcwd config")

    for line in pfcwd_config['stdout_lines']:
        if line.startswith('Ethernet'):
            interface = line.split()[0] # Since line starts with Ethernet, we can safely use 0 index

            cmd = "sonic-db-cli CONFIG_DB hget \"PFC_WD|{}\" \"detection_time\" ".format(interface)
            output = duthost.shell(cmd, module_ignore_errors=True)
            pytest_assert(not output['rc'], "Unable to read detection time")
            detection_time = output["stdout"]

            cmd = "sonic-db-cli CONFIG_DB hget \"PFC_WD|{}\" \"restoration_time\" ".format(interface)
            output = duthost.shell(cmd, module_ignore_errors=True)
            pytest_assert(not output['rc'], "Unable to read restoration time")
            restoration_time = output["stdout"]

            return int(detection_time), int(restoration_time)

    pytest_assert(True, "Failed to read detection_time and/or restoration time")


def get_new_interval(duthost, is_valid):
    """
    Returns new interval value for pfcwd poll interval, based on the operation being performed

    Args:
        duthost: DUT host object
        is_valid: if is_valid is true, return a valid new interval. Config update should succeed. If is_valid is false, return an invalid new interval. Config update should fail.
    """

    detection_time, restoration_time = get_detection_restoration_times(duthost)
    if is_valid:
        return max(detection_time, restoration_time) - 10
    else:
        return min(detection_time, restoration_time) + 10


@pytest.mark.parametrize("oper", ["add", "replace"])
@pytest.mark.parametrize("field_pre_status", ["existing", "nonexistent"])
@pytest.mark.parametrize("is_valid_config_update", [True, False])
def test_pfcwd_interval_config_updates(duthost, ensure_dut_readiness, oper,
                                       field_pre_status, is_valid_config_update):
    new_interval = get_new_interval(duthost, is_valid_config_update)

    operation_to_new_value_map = {"add": "{}".format(new_interval), "replace": "{}".format(new_interval), "remove": ""}
    detection_time, restoration_time = get_detection_restoration_times(duthost)
    pre_status = max(detection_time, restoration_time)
    field_pre_status_to_value_map = {"existing": "{}".format(pre_status), "nonexistent": ""}

    prepare_pfcwd_interval_config(duthost, field_pre_status_to_value_map[field_pre_status])

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {} created for json patch of pfcwd poll interval and operation: {}".format(tmpfile, oper))
    value = operation_to_new_value_map[oper]
    logger.info("value to be added to json patch: {}".format(value))

    json_patch = [
        {
            "op": "{}".format(oper),
            "path": "/PFC_WD/GLOBAL/POLL_INTERVAL",
            "value": "{}".format(value)
        }]

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)

        if is_valid_config_update and is_valid_platform_and_version(duthost, "PFC_WD", "PFCWD enable/disable", oper):
            expect_op_success(duthost, output)
            ensure_application_of_updated_config(duthost, value)
        else:
            expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)
