import ast
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.generic_config_updater.gu_utils import is_valid_platform_and_version, get_asic_name

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical')
]

logger = logging.getLogger(__name__)

READ_ASICDB_TIMEOUT = 20
READ_ASICDB_INTERVAL = 5


@pytest.fixture(scope="function")
def ensure_dut_readiness(duthost):
    """
    Setup/teardown fixture for pg headroom update test

    Args:
        duthost: DUT host object
    """
    verify_orchagent_running_or_assert(duthost)
    create_checkpoint(duthost)

    yield

    try:
        verify_orchagent_running_or_assert(duthost)
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


def ensure_application_of_updated_config(duthost, xoff, values):
    """
    Ensures application of the JSON patch config update

    Args:
        duthost: DUT host object
        values: expected value(s) for the xoff field
    """
    def _confirm_value_in_app_and_asic_db():

        for profile in xoff:
            profile_data = duthost.shell('sonic-db-cli APPL_DB hgetall "BUFFER_PROFILE_TABLE:{}"'
                                         .format(profile))["stdout"]
            profile_data = ast.literal_eval(profile_data)
            if profile_data["xoff"] != xoff[profile]:
                return False

        count = 0
        table_name = duthost.shell('sonic-db-cli ASIC_DB keys *BUFFER_PROFILE*')["stdout_lines"]
        for table in table_name:
            profile_data = duthost.shell('sonic-db-cli ASIC_DB hgetall "{}"'.format(table))["stdout"]
            profile_data = ast.literal_eval(profile_data)
            if "SAI_BUFFER_PROFILE_ATTR_XOFF_TH" in profile_data:
                count += 1
                if profile_data["SAI_BUFFER_PROFILE_ATTR_XOFF_TH"] not in values:
                    return False
        return count == len(values)

    logger.info("Validating fields in APPL DB and ASIC DB...")
    pytest_assert(
        wait_until(READ_ASICDB_TIMEOUT, READ_ASICDB_INTERVAL, 0, _confirm_value_in_app_and_asic_db),
        "APPL DB or ASIC DB does not properly reflect newly configured value(s) for xoff"
    )


@pytest.mark.parametrize("operation", ["replace"])
def test_pg_headroom_update(duthost, ensure_dut_readiness, operation, skip_when_buffer_is_dynamic_model):
    asic_type = get_asic_name(duthost)
    pytest_require("td2" not in asic_type, "PG headroom should be skipped on TD2")
    tmpfile = generate_tmpfile(duthost)

    json_patch = list()
    values = list()
    xoff = dict()
    lossless_profiles = duthost.shell('sonic-db-cli CONFIG_DB keys *BUFFER_PROFILE\\|pg_lossless*')['stdout_lines']
    for profile in lossless_profiles:
        profile_name = profile.split('|')[-1]
        value = duthost.shell('sonic-db-cli CONFIG_DB hget "{}" "xoff"'.format(profile))['stdout']
        value = int(value)
        value -= 1000
        xoff[profile_name] = str(value)
        values.append(str(value))

        logger.info("xoff value to be added to json patch: {}, operation: {}"
                    .format(value, operation))

        json_patch.append(
                          {"op": "{}".format(operation),
                           "path": "/BUFFER_PROFILE/{}/xoff".format(profile_name),
                           "value": "{}".format(value)})

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if is_valid_platform_and_version(duthost, "BUFFER_PROFILE", "PG headroom modification", operation):
            expect_op_success(duthost, output)
            ensure_application_of_updated_config(duthost, xoff, values)
        else:
            expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)
